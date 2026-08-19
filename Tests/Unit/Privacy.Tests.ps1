#Requires -Version 5.1

<#
.SYNOPSIS
    Unit tests for Privacy module

.DESCRIPTION
    Pester v5 tests for the Privacy module functionality.
    Tests return values, DryRun behavior, mode selection, and compliance.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: Pester 5.9.0
#>

BeforeDiscovery {
    # Invoke-PrivacyHardening checks its own token before anything else, so the
    # sealed-decision behavioural tests below can only execute elevated. This is
    # a single explicit environment probe decided at discovery - not a broad
    # catch that converts product failures into green skips.
    $script:RunningElevated = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

BeforeAll {
    # Module entry points prompt through Read-Host unless non-interactive mode
    # is set; the 'Interactive'-tagged smoke tests below run through
    # Invoke-UnitNonInteractive so they cannot block on a real desktop.
    . (Join-Path $PSScriptRoot '_NonInteractive.ps1')
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/Privacy/Privacy.psm1"

    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force
    }
    else {
        throw "Module not found: $modulePath"
    }

    # Import Core modules for testing. NonInteractive.ps1 must be here: the
    # promotion loop below globalizes Test-NonInteractiveMode only if it was
    # loaded, and the module resolves it through the global scope - without it
    # this file only works after another test file happens to promote it.
    $coreModules = @("Logger.ps1", "Config.ps1", "Validator.ps1", "Rollback.ps1", "NonInteractive.ps1")
    $corePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Core"

    foreach ($module in $coreModules) {
        $moduleFile = Join-Path $corePath $module
        if (Test-Path $moduleFile) {
            . $moduleFile
        }
    }

    if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        function global:Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Namespace) $null = $ClassName, $Namespace; throw 'Get-CimInstance test placeholder was not mocked' }
    }
    if (-not (Get-Command Get-Service -ErrorAction SilentlyContinue)) {
        function global:Get-Service { [CmdletBinding()] param([string[]]$Name) $null = $Name; throw 'Get-Service test placeholder was not mocked' }
    }
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        function global:Get-ScheduledTask { [CmdletBinding()] param([string]$TaskName, [string]$TaskPath) $null = $TaskName, $TaskPath; throw 'Get-ScheduledTask test placeholder was not mocked' }
    }
    if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
        function global:Get-AppxPackage {
            [CmdletBinding()]
            param([string]$Name, [string]$User, [object]$PackageTypeFilter)
            $null = $Name, $User, $PackageTypeFilter
            throw 'Get-AppxPackage test placeholder was not mocked'
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

    # Initialize logging (silent for tests)
    if (Get-Command Initialize-Logger -ErrorAction SilentlyContinue) {
        Initialize-Logger -EnableConsole $false
    }
    Set-Item -Path function:global:Write-Log -Value { param($Level, $Message, $Module, $Exception) $null = $Level, $Message, $Module, $Exception }

    # Initialize config
    if (Get-Command Initialize-Config -ErrorAction SilentlyContinue) {
        $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "config.json"
        Initialize-Config -ConfigPath $configPath
    }

    # Initialize backup system
    if (Get-Command Initialize-BackupSystem -ErrorAction SilentlyContinue) {
        Initialize-BackupSystem
    }
}

Describe "Privacy Module" {

    Context "Module Structure" {

        It "Should export Invoke-PrivacyHardening function" {
            $command = Get-Command -Name Invoke-PrivacyHardening -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It "Should export Test-PrivacyCompliance function" {
            $command = Get-Command -Name Test-PrivacyCompliance -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It "Should export the explicitly non-exact Restore-BloatwareApps function" {
            (Get-Command -Name Restore-BloatwareApps -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        }

        It "Should export the read-only Tier 2 restore assessment" {
            (Get-Command -Name Get-BloatwareRestoreAssessment -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        }

        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-PrivacyHardening
            $command.CmdletBinding | Should -Be $true
        }
    }

    Context "Function Parameters" {

        It "Should have Mode parameter" {
            $command = Get-Command -Name Invoke-PrivacyHardening
            $command.Parameters.ContainsKey('Mode') | Should -Be $true
        }

        It "Mode parameter should accept specific values" {
            $command = Get-Command -Name Invoke-PrivacyHardening
            $validateSet = $command.Parameters['Mode'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'MSRecommended'
            $validateSet.ValidValues | Should -Contain 'Strict'
            $validateSet.ValidValues | Should -Contain 'Paranoid'
        }

        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-PrivacyHardening
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }

        It "Should not expose a non-reversible RemoveBloatware parameter" {
            $command = Get-Command -Name Invoke-PrivacyHardening
            $command.Parameters.ContainsKey('RemoveBloatware') | Should -Be $false
        }
    }

    Context "Privacy Mode Configurations" {

        It "Should load MSRecommended config from JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/Privacy/Config/Privacy-MSRecommended.json"
            $configPath | Should -Exist
        }

        It "Should load Strict config from JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/Privacy/Config/Privacy-Strict.json"
            $configPath | Should -Exist
        }

        It "Should load Paranoid config from JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/Privacy/Config/Privacy-Paranoid.json"
            $configPath | Should -Exist
        }

        It "MSRecommended config should be valid JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/Privacy/Config/Privacy-MSRecommended.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It "MSRecommended config should be valid" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/Privacy/Config/Privacy-MSRecommended.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config | Should -Not -BeNullOrEmpty
        }

        It "Strict config should be valid" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/Privacy/Config/Privacy-Strict.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config | Should -Not -BeNullOrEmpty
        }

        It "Strict and Paranoid should disable settings sync and periodic Windows cloud backup" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            foreach ($mode in @('Strict', 'Paranoid')) {
                $configPath = Join-Path $repo "Modules/Privacy/Config/Privacy-$mode.json"
                $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
                $settingSync = $config.InputAndSync.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'

                [string]$settingSync.DisableSettingSync.Type | Should -BeExactly 'DWord'
                [int]$settingSync.DisableSettingSync.Value | Should -Be 2
                [string]$settingSync.DisableSettingSync.Provenance.AdmxFile | Should -BeExactly 'SettingSync.admx'
                [string]$settingSync.DisableSettingSync.Provenance.AdmxPolicy | Should -BeExactly 'DisableSettingSync'
                [string]$settingSync.DisableSettingSync.Provenance.AdmxState | Should -BeExactly 'Enabled'
                [int]$settingSync.DisableSettingSync.Provenance.AdmxValue | Should -Be 2
                [string]$settingSync.DisableSettingSyncUserOverride.Type | Should -BeExactly 'DWord'
                [int]$settingSync.DisableSettingSyncUserOverride.Value | Should -Be 1
                [string]$settingSync.DisableSettingSyncUserOverride.Provenance.AdmxElement | Should -BeExactly 'CheckBox_UserOverride'
                [bool]$settingSync.DisableSettingSyncUserOverride.Provenance.AdmxElementState | Should -BeFalse
                [int]$settingSync.DisableSettingSyncUserOverride.Provenance.AdmxValue | Should -Be 1
                [string]$settingSync.EnableWindowsBackup.Type | Should -BeExactly 'DWord'
                [int]$settingSync.EnableWindowsBackup.Value | Should -Be 0
                [string]$settingSync.EnableWindowsBackup.Provenance.AdmxPolicy | Should -BeExactly 'EnableWindowsBackup'
                [string]$settingSync.EnableWindowsBackup.Provenance.AdmxState | Should -BeExactly 'Disabled'
                [int]$settingSync.EnableWindowsBackup.Provenance.AdmxValue | Should -Be 0
                $settingSync.PSObject.Properties['DisableCredentialsSettingSync'] | Should -BeNullOrEmpty

                $messageSync = $config.InputAndSync.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging'.AllowMessageSync
                [string]$messageSync.Type | Should -BeExactly 'DWord'
                [int]$messageSync.Value | Should -Be 0
                [string]$messageSync.Provenance.AdmxFile | Should -BeExactly 'messaging.admx'
                [string]$messageSync.Provenance.AdmxPolicy | Should -BeExactly 'AllowMessageSync'
                [string]$messageSync.Provenance.AdmxState | Should -BeExactly 'Disabled'
                [int]$messageSync.Provenance.AdmxValue | Should -Be 0
            }

            $paranoid = Get-Content (Join-Path $repo 'Modules/Privacy/Config/Privacy-Paranoid.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            $font = $paranoid.InputAndSync.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'.EnableFontProviders
            [string]$font.Provenance.AdmxFile | Should -BeExactly 'GroupPolicy.admx'
            [string]$font.Provenance.AdmxPolicy | Should -BeExactly 'EnableFontProviders'
            [string]$font.Provenance.AdmxState | Should -BeExactly 'Disabled'
            [int]$font.Value | Should -Be 0
            $metadata = $paranoid.InputAndSync.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'.PreventDeviceMetadataFromNetwork
            [string]$metadata.Provenance.AdmxFile | Should -BeExactly 'DeviceSetup.admx'
            [string]$metadata.Provenance.AdmxPolicy | Should -BeExactly 'DeviceMetadata_PreventDeviceMetadataFromNetwork'
            [string]$metadata.Provenance.AdmxState | Should -BeExactly 'Enabled'
            [int]$metadata.Value | Should -Be 1
        }

        It 'Should execute the inbox ADMX semantic provenance gate and reject wrong semantics' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $tool = Join-Path $repo 'Tools/Test-PrivacyPolicyProvenance.ps1'
            $definitions = Join-Path $TestDrive 'PolicyDefinitions'
            $null = New-Item -Path $definitions -ItemType Directory -Force

            $fixtures = @{
                'SettingSync.admx' = @'
<policyDefinitions><policies>
  <policy name="DisableSettingSync" key="Software\Policies\Microsoft\Windows\SettingSync" valueName="DisableSettingSync">
    <enabledValue><decimal value="2" /></enabledValue>
    <elements><boolean id="CheckBox_UserOverride" valueName="DisableSettingSyncUserOverride"><falseValue><decimal value="1" /></falseValue></boolean></elements>
  </policy>
  <policy name="EnableWindowsBackup" key="Software\Policies\Microsoft\Windows\SettingSync" valueName="EnableWindowsBackup">
    <disabledValue><decimal value="0" /></disabledValue>
  </policy>
</policies></policyDefinitions>
'@
                'messaging.admx' = @'
<policyDefinitions><policies><policy name="AllowMessageSync" key="Software\Policies\Microsoft\Windows\Messaging" valueName="AllowMessageSync"><disabledValue><decimal value="0" /></disabledValue></policy></policies></policyDefinitions>
'@
                'GroupPolicy.admx' = @'
<policyDefinitions><policies><policy name="EnableFontProviders" key="Software\Policies\Microsoft\Windows\System" valueName="EnableFontProviders"><disabledValue><decimal value="0" /></disabledValue></policy></policies></policyDefinitions>
'@
                'DeviceSetup.admx' = @'
<policyDefinitions><policies><policy name="DeviceMetadata_PreventDeviceMetadataFromNetwork" key="SOFTWARE\Policies\Microsoft\Windows\Device Metadata" valueName="PreventDeviceMetadataFromNetwork"><enabledValue><decimal value="1" /></enabledValue></policy></policies></policyDefinitions>
'@
            }
            foreach ($fixture in $fixtures.GetEnumerator()) {
                Set-Content -LiteralPath (Join-Path $definitions $fixture.Key) -Value $fixture.Value -Encoding UTF8
            }

            $settingSync = Join-Path $definitions 'SettingSync.admx'
            $result = & $tool -AdmxPath $settingSync -PolicyDefinitionsRoot $definitions
            $result.Success | Should -Be $true
            $result.TargetsValidated | Should -Be 10
            $result.AdmxFiles.Count | Should -Be 4

            (Get-Content -LiteralPath $settingSync -Raw -Encoding UTF8).Replace(
                '<enabledValue><decimal value="2" /></enabledValue>',
                '<enabledValue><decimal value="1" /></enabledValue>'
            ) | Set-Content -LiteralPath $settingSync -Encoding UTF8
            { & $tool -AdmxPath $settingSync -PolicyDefinitionsRoot $definitions } |
                Should -Throw '*SettingSync ADMX no longer matches*'
        }
    }

    Context "Two-Tier Bloatware Removal (honest restore boundary)" {
        It "Should not ship the old single-tier files that falsely labeled winget reinstall as exact restore" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            (Join-Path $repo 'Modules/Privacy/Private/Remove-Bloatware.ps1') | Should -Not -Exist
            (Join-Path $repo 'Modules/Privacy/Public/Restore-Bloatware.ps1') | Should -Not -Exist
            (Join-Path $repo 'Modules/Privacy/Private/Set-PolicyBasedAppRemoval.ps1') | Should -Not -Exist
        }

        It "Should expose Tier 1, Tier 2, and conditional Weather Widget knobs, all defaulting to off" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $frameworkConfig = Get-Content (Join-Path $repo 'config.json') -Raw | ConvertFrom-Json
            $frameworkConfig.modules.Privacy.applyStorePackagePolicy | Should -Be $false
            $frameworkConfig.modules.Privacy.removeBloatwareApps | Should -Be 'none'
            $frameworkConfig.modules.Privacy.removeWeatherWidget | Should -Be $false
            (Get-Content (Join-Path $repo 'Core/Config.ps1') -Raw) | Should -Match "'none', 'standard'"
        }

        It "Should not claim unavailable WinGet Store fallbacks" {
            InModuleScope Privacy {
                $config = Get-PrivacyBloatwareConfig
                foreach ($contract in @(
                        @{ Name='Microsoft.MicrosoftSolitaireCollection'; Reason='NO_APPLICATIONS_FOUND' },
                        @{ Name='Microsoft.BingNews'; Reason='0x80073CFB' }
                    )) {
                    $mapping = $config.Mappings.([string]$contract.Name)
                    [string]$mapping.StoreId | Should -BeExactly ''
                    @($mapping.ExpectedPackageNames).Count | Should -Be 0
                    [string]$mapping.ReplacementNote | Should -Match ([string]$contract.Reason)
                }
            }
        }

        It "Should pin the exact 27-target Tier 1 policy definition" {
            InModuleScope Privacy {
                $definition = Get-PrivacyTier1PolicyDefinition
                @($definition.Targets).Count | Should -Be 27
                @($definition.RemovalTargets).Count | Should -Be 8
                @($definition.Targets | Where-Object { $_.Name -eq 'Enabled' -and $_.Value -eq 1 }).Count | Should -Be 1
                $dynamic = @($definition.Targets | Where-Object { $_.Name -eq 'DynamicRemovalList' })
                $dynamic.Count | Should -Be 1
                $dynamic[0].Type | Should -BeExactly 'MultiString'
                @($dynamic[0].Value).Count | Should -Be 0
                @($definition.Targets | Where-Object {
                        $_.Path -match '\\Microsoft\.BingNews_8wekyb3d8bbwe$' -and
                        $_.Name -eq 'RemovePackage' -and $_.Value -eq 1
                    }).Count | Should -Be 1
                @($definition.Targets | Where-Object {
                        $_.Path -match '\\Microsoft\.Copilot_8wekyb3d8bbwe$' -and
                        $_.Name -eq 'RemovePackage' -and $_.Value -eq 1
                    }).Count | Should -Be 1
                @($definition.Targets | Where-Object {
                        $_.Path -match '\\BingNews$|\\XboxGamingOverlay$'
                    }).Count | Should -Be 0
            }
        }

        It "Should retain the complete v2.2.5 Tier 1 contract for restore only" {
            InModuleScope Privacy {
                $legacy = Get-PrivacyTier1LegacyV225PolicyDefinition
                @($legacy.Targets).Count | Should -Be 27
                @($legacy.RemovalTargets).Count | Should -Be 9
                @($legacy.Targets | Where-Object {
                        $_.Path -match '\\MicrosoftStickyNotes$|\\XboxGamingOverlay$' -and
                        $_.Name -eq 'RemovePackage' -and $_.Value -eq 1
                    }).Count | Should -Be 2

                $currentCatalog = Get-PrivacyTier1AppCatalog
                $previousCatalog = Get-PrivacyTier1AppCatalog -PreviousV33
                $preCopilotCatalog = Get-PrivacyTier1AppCatalog -PreCopilot
                $legacyCatalog = Get-PrivacyTier1AppCatalog -LegacyV225
                $currentCatalog.Contract | Should -BeExactly 'CurrentPFN'
                $previousCatalog.Contract | Should -BeExactly 'PreviousV33PFN'
                $preCopilotCatalog.Contract | Should -BeExactly 'PreCopilotPFN'
                $legacyCatalog.Contract | Should -BeExactly 'LegacyV225'
                @($currentCatalog.Apps).Count | Should -Be 8
                @($previousCatalog.Apps).Count | Should -Be 8
                @($preCopilotCatalog.Apps).Count | Should -Be 7
                @($legacyCatalog.Apps).Count | Should -Be 9
                $preCopilotCatalog.PolicySha256 | Should -BeExactly '1a1db769db1c330624a682812c80aa822ec9e5203535e6d97007a70e6041896f'
                $preCopilotCatalog.CatalogSha256 | Should -BeExactly 'd49968d0b86d8a03b8c52582b59e067a169971c92a3f39ebff11ce49453f19f3'
                $previousCatalog.CatalogSha256 | Should -BeExactly '9f46fbd428cd4922290c8644fff25bebec88cb8a531604c69d430bb1a5398e9a'
                [string]($previousCatalog.Apps | Where-Object AppName -eq 'Microsoft.BingNews').StoreId |
                    Should -BeExactly '9WZDNCRFHVFW'
                [string]($currentCatalog.Apps | Where-Object AppName -eq 'Microsoft.BingNews').StoreId |
                    Should -BeExactly ''
                $legacyCatalog.PolicySha256 | Should -Not -BeExactly $currentCatalog.PolicySha256
            }
        }

        It "Should classify Tier 1 as supported only on unmanaged single-session Enterprise/Education 24H2+" {
            InModuleScope Privacy {
                $enterprise24H2 = [PSCustomObject]@{
                    EditionFamily = 'Enterprise'; WindowsManagedPolicySupported = $true; EnterprisePolicySupported = $true
                    Tier1PolicyRemovalOsSupported = $true; Tier1PolicyRemovalSupported = $true
                    DomainJoined = $false; MdmRegistered = $false; ManagementStateKnown = $true
                }
                (Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages' -Name 'Enabled' -Applicability $enterprise24H2).Applicable | Should -BeTrue
                (Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.BingNews_8wekyb3d8bbwe' -Name 'RemovePackage' -Applicability $enterprise24H2).Applicable | Should -BeTrue

                $professional = [PSCustomObject]@{
                    EditionFamily = 'Professional'; WindowsManagedPolicySupported = $true; EnterprisePolicySupported = $false
                    Tier1PolicyRemovalOsSupported = $false; Tier1PolicyRemovalSupported = $false
                    DomainJoined = $false; MdmRegistered = $false; ManagementStateKnown = $true
                }
                (Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.BingNews_8wekyb3d8bbwe' -Name 'RemovePackage' -Applicability $professional).Applicable | Should -BeFalse

                $homeEditionContext = [PSCustomObject]@{
                    EditionFamily = 'Home'; WindowsManagedPolicySupported = $false; EnterprisePolicySupported = $false
                    Tier1PolicyRemovalOsSupported = $false; Tier1PolicyRemovalSupported = $false
                    DomainJoined = $false; MdmRegistered = $false; ManagementStateKnown = $true
                }
                (Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.BingNews_8wekyb3d8bbwe' -Name 'RemovePackage' -Applicability $homeEditionContext).Applicable | Should -BeFalse

                $enterpriseOldBuild = [PSCustomObject]@{
                    EditionFamily = 'Enterprise'; WindowsManagedPolicySupported = $true; EnterprisePolicySupported = $true
                    Tier1PolicyRemovalOsSupported = $false; Tier1PolicyRemovalSupported = $false
                    DomainJoined = $false; MdmRegistered = $false; ManagementStateKnown = $true
                }
                (Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.BingNews_8wekyb3d8bbwe' -Name 'RemovePackage' -Applicability $enterpriseOldBuild).Applicable | Should -BeFalse

                $managedEnterprise = [PSCustomObject]@{
                    EditionFamily = 'Enterprise'; WindowsManagedPolicySupported = $true; EnterprisePolicySupported = $true
                    Tier1PolicyRemovalOsSupported = $true; Tier1PolicyRemovalSupported = $false
                    DomainJoined = $true; MdmRegistered = $false; ManagementStateKnown = $true
                }
                $managedResult = Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.BingNews_8wekyb3d8bbwe' -Name 'RemovePackage' -Applicability $managedEnterprise
                $managedResult.Applicable | Should -BeFalse
                $managedResult.Reason | Should -Match 'authoritative channel'

                $unknownManagement = [PSCustomObject]@{
                    EditionFamily = 'Enterprise'; WindowsManagedPolicySupported = $true; EnterprisePolicySupported = $true
                    Tier1PolicyRemovalOsSupported = $true; Tier1PolicyRemovalSupported = $false
                    DomainJoined = $false; MdmRegistered = $false; ManagementStateKnown = $false
                }
                $unknownResult = Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.BingNews_8wekyb3d8bbwe' -Name 'RemovePackage' -Applicability $unknownManagement
                $unknownResult.Applicable | Should -BeFalse
                $unknownResult.Reason | Should -Match 'could not be proven'

                $legacyMock = [PSCustomObject]@{ EditionFamily = 'Enterprise'; WindowsManagedPolicySupported = $true; EnterprisePolicySupported = $true }
                (Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.BingNews_8wekyb3d8bbwe' -Name 'RemovePackage' -Applicability $legacyMock).Applicable | Should -BeFalse
            }
        }

        It "Should keep all 27 Tier 1 targets declared when the default decision is No" {
            InModuleScope Privacy {
                Mock Get-PrivacyUserContext { [PSCustomObject]@{ Sid='S-1-5-21-1-2-3-1001'; Root='HKU:\S-1-5-21-1-2-3-1001' } }
                $config = Get-Content (Join-Path $script:ModuleRoot 'Config/Privacy-MSRecommended.json') -Raw | ConvertFrom-Json
                $config | Add-Member -NotePropertyName Tier1PolicyRemovalSelected -NotePropertyValue $false -Force
                $applicability = [PSCustomObject]@{
                    EditionFamily='Enterprise'; WindowsManagedPolicySupported=$true; EnterprisePolicySupported=$true
                    Tier1PolicyRemovalOsSupported=$true; Tier1PolicyRemovalSupported=$true
                    DomainJoined=$false; MdmRegistered=$false; ManagementStateKnown=$true; MultiSession=$false
                }
                $plan = Get-PrivacyTargetPlan -Config $config -Applicability $applicability
                $plan.DeclaredCount | Should -Be 63
                @($plan.NotCheckedTargets).Count | Should -Be 27
                @($plan.ApplicableTargets).Count | Should -Be 36

                $config.Tier1PolicyRemovalSelected = $true
                $selectedPlan = Get-PrivacyTargetPlan -Config $config -Applicability $applicability
                @($selectedPlan.NotCheckedTargets).Count | Should -Be 0
                @($selectedPlan.ApplicableTargets).Count | Should -Be 63
            }
        }

        It "Should compute the Tier 1 OS, management, and multi-session gates fail closed" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $source = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Get-PrivacyApplicability.ps1') -Raw
            $source | Should -Match 'Tier1PolicyRemovalOsSupported'
            $source | Should -Match 'Tier1PolicyRemovalSupported = \$tier1OsSupported -and -not \[bool\]\$management\.ExternallyManaged'
            $source | Should -Match 'ServerRdsh\|MultiSession'
            $source | Should -Match 'ManagementStateKnown'
        }

        It "Should isolate management-query failure to the Tier 1 applicability gate" {
            InModuleScope Privacy {
                Mock Get-CimInstance { throw 'CIM unavailable' }
                Mock Test-PrivacyMdmRegistration { throw 'MDM API unavailable' }
                Mock Write-Log {}
                $management = Get-PrivacyManagementState
                $management.StateKnown | Should -BeFalse
                $management.ExternallyManaged | Should -BeTrue
                @($management.QueryErrors).Count | Should -Be 2
                Should -Invoke Write-Log -Times 1 -Exactly
            }
        }

        It "seals all three destructive decisions as N when every prompt takes its default" -Skip:(-not $script:RunningElevated) {
            # The prompt-source regexes below prove the prompts SAY default N;
            # only driving the function proves the sealed config AGREES. The two
            # can diverge - Tier2BloatwareRemovalSelected once read a variable
            # that did not exist in the file - so the decision, not the prose,
            # is the contract.
            $global:PrivacyTestPromptQueue = [System.Collections.Generic.Queue[string]]::new()
            # Strict mode: no cloud-clipboard prompt; tier1 then tier2, both by
            # default. No weather prompt because tier2 stays 'none'.
            # The Tier 1 prompt itself is edition-gated: on a Pro host the real
            # Get-PrivacyApplicability skips it and seals $false fail-closed, so
            # the eligible-host prompt path must be pinned by mock, not by the
            # edition this test happens to run on. The interactive mode must be
            # pinned too: Run-AllTests.ps1 exports NOIDPRIVACY_NONINTERACTIVE
            # and the real Test-NonInteractiveMode then throws on the env/config
            # contradiction instead of prompting.
            Mock -ModuleName Privacy Test-NonInteractiveMode { $false }
            Mock -ModuleName Privacy Get-PrivacyApplicability {
                [PSCustomObject]@{
                    EditionFamily = 'Enterprise'; BuildNumber = 26100
                    WindowsManagedPolicySupported = $true; EnterprisePolicySupported = $true
                    Tier1PolicyRemovalOsSupported = $true; Tier1PolicyRemovalSupported = $true
                    DomainJoined = $false; MdmRegistered = $false; ManagementStateKnown = $true; MultiSession = $false
                }
            }
            Mock -ModuleName Privacy Read-Host {
                if ($global:PrivacyTestPromptQueue.Count -eq 0) { return '' }
                $global:PrivacyTestPromptQueue.Dequeue()
            }
            Mock -ModuleName Privacy Get-PrivacyRuntimeTargetPlan {
                $global:PrivacyTestSealedConfig = $Config
                [PSCustomObject]@{ DeclaredChecks = 88; ApplicableChecks = 88; NotCheckedChecks = 0; NotApplicableChecks = 0 }
            }

            $result = Invoke-PrivacyHardening -Mode Strict -DryRun
            $result.Success | Should -BeTrue
            $result.Status | Should -BeExactly 'DryRun'
            [bool]$global:PrivacyTestSealedConfig.Tier1PolicyRemovalSelected | Should -BeFalse
            [bool]$global:PrivacyTestSealedConfig.Tier2BloatwareRemovalSelected | Should -BeFalse
            [bool]$global:PrivacyTestSealedConfig.WeatherWidgetRemovalSelected | Should -BeFalse
        }

        It "seals all three destructive decisions as selected when the operator answers Y" -Skip:(-not $script:RunningElevated) {
            $global:PrivacyTestPromptQueue = [System.Collections.Generic.Queue[string]]::new()
            foreach ($answer in @('Y', 'Y', 'Y')) { $global:PrivacyTestPromptQueue.Enqueue($answer) }
            # Same edition and interactive-mode pins as the default-N case:
            # without them the Tier 1 prompt never fires on a Pro host (first Y
            # misdelivered to Tier 2) and Run-AllTests' exported non-interactive
            # env var makes Test-NonInteractiveMode throw instead of prompting.
            Mock -ModuleName Privacy Test-NonInteractiveMode { $false }
            Mock -ModuleName Privacy Get-PrivacyApplicability {
                [PSCustomObject]@{
                    EditionFamily = 'Enterprise'; BuildNumber = 26100
                    WindowsManagedPolicySupported = $true; EnterprisePolicySupported = $true
                    Tier1PolicyRemovalOsSupported = $true; Tier1PolicyRemovalSupported = $true
                    DomainJoined = $false; MdmRegistered = $false; ManagementStateKnown = $true; MultiSession = $false
                }
            }
            Mock -ModuleName Privacy Read-Host {
                if ($global:PrivacyTestPromptQueue.Count -eq 0) { return '' }
                $global:PrivacyTestPromptQueue.Dequeue()
            }
            Mock -ModuleName Privacy Get-PrivacyRuntimeTargetPlan {
                $global:PrivacyTestSealedConfig = $Config
                [PSCustomObject]@{ DeclaredChecks = 88; ApplicableChecks = 88; NotCheckedChecks = 0; NotApplicableChecks = 0 }
            }

            $result = Invoke-PrivacyHardening -Mode Strict -DryRun
            $result.Success | Should -BeTrue
            [bool]$global:PrivacyTestSealedConfig.Tier1PolicyRemovalSelected | Should -BeTrue
            [bool]$global:PrivacyTestSealedConfig.Tier2BloatwareRemovalSelected | Should -BeTrue
            [bool]$global:PrivacyTestSealedConfig.WeatherWidgetRemovalSelected | Should -BeTrue

            Remove-Variable -Name PrivacyTestPromptQueue, PrivacyTestSealedConfig -Scope Global -ErrorAction SilentlyContinue
        }

        It "Should default Tier 1, Tier 2, and conditional Weather Widget prompts to N and seal every decision" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $invoke = Get-Content (Join-Path $repo 'Modules/Privacy/Public/Invoke-PrivacyHardening.ps1') -Raw
            $invoke | Should -Match '\[Y/N\] \(default: N\): " -ForegroundColor Yellow -NoNewline\s*\r?\n\s*\$tier1Answer = Read-Host\s*\r?\n\s*if \(\[string\]::IsNullOrWhiteSpace\(\$tier1Answer\)\) \{ \$tier1Answer = "N" \}'
            $invoke | Should -Match '\[Y/N\] \(default: N\): " -ForegroundColor Yellow -NoNewline\s*\r?\n\s*\$tier2Answer = Read-Host\s*\r?\n\s*if \(\[string\]::IsNullOrWhiteSpace\(\$tier2Answer\)\) \{ \$tier2Answer = "N" \}'
            $invoke | Should -Match '\[Y/N\] \(default: N\): " -ForegroundColor Yellow -NoNewline\s*\r?\n\s*\$weatherWidgetAnswer = Read-Host\s*\r?\n\s*if \(\[string\]::IsNullOrWhiteSpace\(\$weatherWidgetAnswer\)\) \{ \$weatherWidgetAnswer = ''N'' \}'
            $invoke | Should -Match "Add-Member -NotePropertyName 'Tier1PolicyRemovalSelected'"
            $invoke | Should -Match "Add-Member -NotePropertyName 'Tier2BloatwareRemovalSelected'"
            $invoke | Should -Match "Add-Member -NotePropertyName 'WeatherWidgetRemovalSelected'"
            $invoke | Should -Match 'Get-NonInteractiveValue -Module "Privacy" -Key "applyStorePackagePolicy" -Required'
            $invoke | Should -Match 'Get-NonInteractiveValue -Module "Privacy" -Key "removeBloatwareApps" -Required'
            $invoke | Should -Match 'Get-NonInteractiveValue -Module "Privacy" -Key "removeWeatherWidget" -Required'
            $invoke | Should -Not -Match 'Get-NonInteractiveValue -Module "Privacy" -Key "(?:applyStorePackagePolicy|removeBloatwareApps|removeWeatherWidget)" -Default'
            $invoke | Should -Match 'Local data belonging to a removed app can be deleted'
            $invoke | Should -Match 'Applies device-wide to every user'
        }

        It "Should suppress the native High-impact confirmation at the sealed Tier 2 apply call site" {
            # The module's own default-No prompt (or the explicit noninteractive
            # opt-in) is the consent; the native prompt would invert the default
            # and stall the GUI's hidden-console host.
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $invoke = Get-Content (Join-Path $repo 'Modules/Privacy/Public/Invoke-PrivacyHardening.ps1') -Raw
            $invoke | Should -Match 'Remove-BloatwareApps -ActionLog \$privacyBloatwareActionLog -Confirm:\$false'
        }

        It "Should remove sealed identities only through the limited interactive-user worker and independently reject pending state" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $removeSource = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Remove-BloatwareApps.ps1') -Raw
            $workerSource = Get-Content (Join-Path $repo 'Modules/Privacy/Private/PrivacyUserAppx.ps1') -Raw
            $moduleSource = Get-Content (Join-Path $repo 'Modules/Privacy/Privacy.psm1') -Raw
            $removeSource | Should -Match 'Invoke-PrivacyUserAppxRemoval -User \$userContext -Entries \$presentEntries'
            $removeSource | Should -Not -Match 'Remove-AppxPackage'
            $removeSource | Should -Not -Match 'SilentlyContinue'
            $workerSource | Should -Match 'Remove-AppxPackage -Package \$fullName -ErrorAction Stop'
            $tokens = $null
            $parseErrors = $null
            $workerAst = [Management.Automation.Language.Parser]::ParseInput(
                $workerSource, [ref]$tokens, [ref]$parseErrors
            )
            @($parseErrors).Count | Should -Be 0
            $removeCommands = @($workerAst.FindAll({
                        param($node)
                        $node -is [Management.Automation.Language.CommandAst] -and
                            $node.GetCommandName() -eq 'Remove-AppxPackage'
                    }, $true))
            $removeCommands.Count | Should -Be 1
            @($removeCommands[0].CommandElements | Where-Object {
                    $_ -is [Management.Automation.Language.CommandParameterAst] -and
                        $_.ParameterName -eq 'User'
                }).Count | Should -Be 0
            $workerSource | Should -Match 'New-ScheduledTaskPrincipal[\s\S]*-LogonType Interactive -RunLevel Limited'
            $workerSource | Should -Match 'Get-PrivacyUserContext -Refresh'
            $workerSource | Should -Match 'Get-AppxPackage -AllUsers -Name'
            $workerSource | Should -Match 'target-user state'
            $workerSource | Should -Match 'Restore-PrivacyAppxFirewallState -State \$firewallPrestate[\s\S]*-Scope OtherUsers -TargetUserSid \$sid'
            $moduleSource.IndexOf("'PrivacyUserAppx'", [StringComparison]::Ordinal) |
                Should -BeLessThan $moduleSource.IndexOf("'Remove-BloatwareApps'", [StringComparison]::Ordinal)
            $configLoaderSource = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Get-PrivacyBloatwareConfig.ps1') -Raw
            $configLoaderSource | Should -Match 'RemoveApps overlaps ProtectedApps'
            $configLoaderSource | Should -Match 'exactly one mapping for every removal-list app'
        }

        It "Should seal a parent Bundle instead of its Main child, with Main as the exact fallback" {
            InModuleScope Privacy {
                $script:testConfig = [PSCustomObject]@{
                    RemoveApps = @('Test.BundleApp','Test.MainApp')
                    OptionalRemoveApps = [PSCustomObject]@{ WeatherWidget = 'Test.Widget' }
                    Mappings = [PSCustomObject]@{
                        'Test.BundleApp' = [PSCustomObject]@{ StoreId=''; ExpectedPackageNames=@() }
                        'Test.MainApp' = [PSCustomObject]@{ StoreId=''; ExpectedPackageNames=@() }
                    }
                    CatalogSha256 = ('a' * 64)
                }
                Mock Get-PrivacyBloatwareConfig { $script:testConfig }
                Mock Get-PrivacyUserContext { [PSCustomObject]@{ Sid='S-1-5-21-1-2-3-1001' } }
                Mock Get-AppxProvisionedPackage { @() }
                Mock Get-PrivacyBloatwareInventoryFingerprint { 'b' * 64 }
                $script:capturedInventoryPackageTypeFilters = [Collections.Generic.List[string]]::new()
                Mock Get-AppxPackage {
                    param($Name, $User, $PackageTypeFilter)
                    $null = $User
                    $script:capturedInventoryPackageTypeFilters.Add(
                        (@($PackageTypeFilter | ForEach-Object { [string]$_ }) -join ',')
                    )
                    if ($Name -eq 'Test.BundleApp') {
                        @(
                            [PSCustomObject]@{ IsBundle=$false; PackageFullName='Test.BundleApp_1.0_x64__test'; PackageFamilyName='Test.BundleApp_test'; Version='1.0' },
                            [PSCustomObject]@{ IsBundle=$true; PackageFullName='Test.BundleApp_2.0_neutral_~_test'; PackageFamilyName='Test.BundleApp_test'; Version='2.0' }
                        )
                    }
                    else {
                        [PSCustomObject]@{ IsBundle=$false; PackageFullName='Test.MainApp_1.0_x64__test'; PackageFamilyName='Test.MainApp_test'; Version='1.0' }
                    }
                }

                $log = Get-PrivacyBloatwareActionLog
                @($log.Entries).Count | Should -Be 2
                [string](@($log.Entries | Where-Object AppName -eq 'Test.BundleApp')[0].PackageFullName) |
                    Should -BeExactly 'Test.BundleApp_2.0_neutral_~_test'
                [string](@($log.Entries | Where-Object AppName -eq 'Test.MainApp')[0].PackageFullName) |
                    Should -BeExactly 'Test.MainApp_1.0_x64__test'
                Should -Invoke Get-AppxPackage -Times 2 -Exactly
                @($script:capturedInventoryPackageTypeFilters).Count | Should -Be 2
                ($script:capturedInventoryPackageTypeFilters -join '|') |
                    Should -BeExactly 'Main, Bundle|Main, Bundle'
            }
        }

        It "Should delegate the exact sealed Bundle or Main identities to the Explorer-user worker" {
            InModuleScope Privacy {
                $actionLog = [PSCustomObject]@{
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    Entries = @(
                        [PSCustomObject]@{ Present=$true; AppName='Test.BundleApp'; PackageFullName='Test.BundleApp_2.0_neutral_~_test' },
                        [PSCustomObject]@{ Present=$true; AppName='Test.MainApp'; PackageFullName='Test.MainApp_1.0_x64__test' }
                    )
                }
                Mock Assert-PrivacyBloatwareActionLog { $true }
                Mock Get-PrivacyUserContext {
                    [PSCustomObject]@{ Account='TEST\standard';Sid='S-1-5-21-1-2-3-1001';SessionId=2 }
                }
                Mock Invoke-PrivacyUserAppxRemoval {
                    [PSCustomObject]@{
                        Success=$true;TargetPackages=2;Removed=2;Failed=0
                        Entries=@(
                            [PSCustomObject]@{AppName='Test.BundleApp';PackageFullName='Test.BundleApp_2.0_neutral_~_test';Removed=$true;Error=''},
                            [PSCustomObject]@{AppName='Test.MainApp';PackageFullName='Test.MainApp_1.0_x64__test';Removed=$true;Error=''}
                        )
                    }
                }
                Mock Write-Log {}

                $result = Remove-BloatwareApps -ActionLog $actionLog -Confirm:$false
                $result.Success | Should -BeTrue
                $result.TargetPackages | Should -Be 2
                $result.Removed | Should -Be 2
                $result.Failed | Should -Be 0
                Should -Invoke Invoke-PrivacyUserAppxRemoval -Times 1 -Exactly -ParameterFilter {
                    [string]$User.Account -ceq 'TEST\standard' -and
                    [string]$User.Sid -ceq 'S-1-5-21-1-2-3-1001' -and
                    [int]$User.SessionId -eq 2 -and @($Entries).Count -eq 2 -and
                    @($Entries | ForEach-Object { [string]$_.PackageFullName } | Sort-Object) -join '|' -ceq
                        'Test.BundleApp_2.0_neutral_~_test|Test.MainApp_1.0_x64__test'
                }
            }
        }

        It "Should fail closed when the Explorer-user worker reports a pending-registration postcondition" {
            InModuleScope Privacy {
                $actionLog = [PSCustomObject]@{
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    Entries = @([PSCustomObject]@{
                            Present=$true; AppName='Test.BundleApp'; PackageFullName='Test.BundleApp_2.0_neutral_~_test'
                        })
                }
                Mock Assert-PrivacyBloatwareActionLog { $true }
                Mock Get-PrivacyUserContext {
                    [PSCustomObject]@{ Account='TEST\standard';Sid='S-1-5-21-1-2-3-1001';SessionId=2 }
                }
                Mock Invoke-PrivacyUserAppxRemoval {
                    throw 'Privacy AppX removal did not reach an absent target-user state: Test.BundleApp'
                }
                Mock Write-Log {}

                $result = Remove-BloatwareApps -ActionLog $actionLog -Confirm:$false
                $result.Success | Should -BeFalse
                $result.Removed | Should -Be 0
                $result.Failed | Should -Be 1
                [string]$result.FailedApps[0] | Should -Match 'absent target-user state'
            }
        }

        It "Should stop a failed partial worker before preserving other-user firewall collateral" {
            InModuleScope Privacy {
                $targetSid = 'S-1-5-21-1-2-3-1001'
                $user = [PSCustomObject]@{Account='TEST\standard';Sid=$targetSid;SessionId=2}
                $entries = @([PSCustomObject]@{
                        Present=$true;AppName='Test.BundleApp'
                        PackageFullName='Test.BundleApp_2.0_neutral_~_test'
                        PackageFamilyName='Test.BundleApp_testpub'
                    })
                $firewallState = [PSCustomObject]@{Marker='sealed-firewall-state'}
                $workerRecord = [ordered]@{
                    SchemaVersion=1;CapturedUtc=[DateTime]::UtcNow.ToString('o')
                    User='TEST\standard';Sid=$targetSid;SessionId=2;TargetPackages=1
                    Removed=0;Failed=1
                    Entries=@([PSCustomObject]@{
                            AppName='Test.BundleApp';PackageFullName='Test.BundleApp_2.0_neutral_~_test'
                            Removed=$false;Error='simulated partial worker failure'
                        })
                    Success=$false;Error='simulated partial worker failure'
                }
                $directory = [PSCustomObject]@{}
                $directory | Add-Member -MemberType ScriptMethod -Name SetAccessControl -Value {
                    param($Security)
                    $null = $Security
                }
                $resultFile = [PSCustomObject]@{Attributes=[IO.FileAttributes]::Normal;Length=128}
                $script:failedWorkerTaskReads = 0
                $script:failedWorkerCleanupEvents = [Collections.Generic.List[string]]::new()

                Mock Get-PrivacyUserContext { $user }
                Mock Get-PrivacyAppxFirewallState { $firewallState }
                Mock Test-Path { $true }
                Mock New-Item { $directory }
                Mock Register-ScheduledTask {}
                Mock Start-ScheduledTask {}
                Mock Get-ScheduledTask {
                    $script:failedWorkerTaskReads++
                    if ($script:failedWorkerTaskReads -eq 2) { [PSCustomObject]@{State='Running'} }
                    else { [PSCustomObject]@{State='Ready'} }
                }
                Mock Stop-ScheduledTask { $script:failedWorkerCleanupEvents.Add('stop') }
                Mock Unregister-ScheduledTask { $script:failedWorkerCleanupEvents.Add('unregister') }
                Mock Get-ScheduledTaskInfo { [PSCustomObject]@{LastTaskResult=0} }
                Mock Get-Item { $resultFile }
                Mock Get-Content { ConvertTo-Json -InputObject $workerRecord -Depth 8 }
                Mock Restore-PrivacyAppxFirewallState {
                    $script:failedWorkerCleanupEvents.Add('restore')
                    [PSCustomObject]@{Success=$true;Restored=1;Removed=0;Verified=1;Scope='OtherUsers'}
                }
                Mock Remove-Item { $script:failedWorkerCleanupEvents.Add('remove') }

                { Invoke-PrivacyUserAppxRemoval -User $user -Entries $entries -TimeoutSeconds 30 } |
                    Should -Throw '*simulated partial worker failure*'
                ($script:failedWorkerCleanupEvents -join '|') |
                    Should -BeExactly 'stop|unregister|restore|remove'
                Should -Invoke Stop-ScheduledTask -Times 1 -Exactly
                Should -Invoke Unregister-ScheduledTask -Times 1 -Exactly
                Should -Invoke Restore-PrivacyAppxFirewallState -Times 1 -Exactly -ParameterFilter {
                    $State -eq $firewallState -and [string]$Scope -ceq 'OtherUsers' -and
                    [string]$TargetUserSid -ceq $targetSid
                }
            }
        }

        It "Should succeed without creating a task when no sealed package was installed" {
            InModuleScope Privacy {
                $actionLog = [PSCustomObject]@{
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    Entries = @([PSCustomObject]@{
                            Present=$false;AppName='Test.BundleApp';PackageFullName=$null
                        })
                }
                Mock Assert-PrivacyBloatwareActionLog { $true }
                Mock Get-PrivacyUserContext {
                    [PSCustomObject]@{ Account='TEST\standard';Sid='S-1-5-21-1-2-3-1001';SessionId=2 }
                }
                Mock Invoke-PrivacyUserAppxRemoval { throw 'must not run' }
                Mock Write-Log {}

                $result = Remove-BloatwareApps -ActionLog $actionLog -Confirm:$false
                $result.Success | Should -BeTrue
                $result.TargetPackages | Should -Be 0
                $result.Removed | Should -Be 0
                $result.Failed | Should -Be 0
                Should -Invoke Invoke-PrivacyUserAppxRemoval -Times 0 -Exactly
            }
        }

        It "Should load the optional Weather catalog under Windows PowerShell StrictMode" {
            InModuleScope Privacy {
                $config = & {
                    Set-StrictMode -Version Latest
                    Get-PrivacyBloatwareConfig
                }

                @($config.OptionalRemoveApps.PSObject.Properties).Count | Should -Be 1
                $config.OptionalRemoveApps.WeatherWidget | Should -BeExactly 'MicrosoftWindows.Client.WebExperience'
                @($config.AllRemoveApps).Count | Should -Be 27
            }
        }

        It "Should seal the Tier 2 action-log artifact before removal, with a validated schema" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $backupSource = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Backup-PrivacySettings.ps1') -Raw
            $backupSource | Should -Match "Register-Backup -Type 'Privacy' -Data \`$actionLog -Name 'Privacy_BloatwareActions'"
            $backupSource | Should -Match 'Assert-PrivacyBloatwareActionLog -ActionLog \$actionLog'
            $backupSource | Should -Match 'Assert-PrivacyBloatwareActionLog -ActionLog \$roundTripLog'

            InModuleScope Privacy {
                $config = Get-PrivacyBloatwareConfig
                $entries = @($config.AllRemoveApps | ForEach-Object {
                        $mapping = $config.Mappings.$_
                        [PSCustomObject]@{
                            AppName=$_; Present=$false; PackageFullName=$null; PackageFamilyName=$null; Version=$null
                            ProvisionedPackageNames=@(); StoreId=[string]$mapping.StoreId
                            ExpectedPackageNames=@($mapping.ExpectedPackageNames)
                        }
                    })
                $validLog = [PSCustomObject]@{
                    SchemaVersion = 2; Mode = 'standard'; InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    Timestamp = (Get-Date).ToUniversalTime().ToString('o'); CatalogSha256=$config.CatalogSha256
                    InventorySha256=(Get-PrivacyBloatwareInventoryFingerprint -Entries $entries); Entries=$entries
                }
                (Assert-PrivacyBloatwareActionLog -ActionLog $validLog) | Should -BeTrue

                $previous = Get-PrivacyBloatwareConfig -PreviousV33
                $previousEntries = @($previous.AllRemoveApps | ForEach-Object {
                        $mapping = $previous.Mappings.$_
                        [PSCustomObject]@{
                            AppName=$_; Present=$false; PackageFullName=$null; PackageFamilyName=$null; Version=$null
                            ProvisionedPackageNames=@(); StoreId=[string]$mapping.StoreId
                            ExpectedPackageNames=@($mapping.ExpectedPackageNames)
                        }
                    })
                $previousLog = [PSCustomObject]@{
                    SchemaVersion = 3; Mode = 'standard'; WeatherWidgetRemovalSelected = $true
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    Timestamp = (Get-Date).ToUniversalTime().ToString('o'); CatalogSha256=$previous.CatalogSha256
                    InventorySha256=(Get-PrivacyBloatwareInventoryFingerprint -Entries $previousEntries); Entries=$previousEntries
                }
                (Assert-PrivacyBloatwareActionLog -ActionLog $previousLog) | Should -BeTrue

                $preCopilot = Get-PrivacyBloatwareConfig -PreCopilot
                $preCopilotEntries = @($preCopilot.AllRemoveApps | ForEach-Object {
                        $mapping = $preCopilot.Mappings.$_
                        [PSCustomObject]@{
                            AppName=$_; Present=$false; PackageFullName=$null; PackageFamilyName=$null; Version=$null
                            ProvisionedPackageNames=@(); StoreId=[string]$mapping.StoreId
                            ExpectedPackageNames=@($mapping.ExpectedPackageNames)
                        }
                    })
                $preCopilotLog = [PSCustomObject]@{
                    SchemaVersion = 2; Mode = 'standard'; InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    Timestamp = (Get-Date).ToUniversalTime().ToString('o'); CatalogSha256=$preCopilot.CatalogSha256
                    InventorySha256=(Get-PrivacyBloatwareInventoryFingerprint -Entries $preCopilotEntries); Entries=$preCopilotEntries
                }
                (Assert-PrivacyBloatwareActionLog -ActionLog $preCopilotLog) | Should -BeTrue

                $baseEntries = @($entries | Where-Object { $_.AppName -ne $config.OptionalRemoveApps.WeatherWidget })
                $currentLog = [PSCustomObject]@{
                    SchemaVersion = 3; Mode = 'standard'; WeatherWidgetRemovalSelected = $false
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    Timestamp = (Get-Date).ToUniversalTime().ToString('o'); CatalogSha256=$config.CatalogSha256
                    InventorySha256=(Get-PrivacyBloatwareInventoryFingerprint -Entries $baseEntries); Entries=$baseEntries
                }
                (Assert-PrivacyBloatwareActionLog -ActionLog $currentLog) | Should -BeTrue
                $currentLog.WeatherWidgetRemovalSelected = $true
                { Assert-PrivacyBloatwareActionLog -ActionLog $currentLog } | Should -Throw '*missing catalog app*'

                $invalidLog = $validLog.PSObject.Copy()
                $invalidLog.CatalogSha256 = ('0' * 64)
                { Assert-PrivacyBloatwareActionLog -ActionLog $invalidLog } | Should -Throw '*different removal/reinstall catalog*'
            }
        }

        It "Should seal Tier 1, Weather Widget, and exact AppX firewall collateral in Privacy schema 7" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $backupSource = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Backup-PrivacySettings.ps1') -Raw
            $prestateSource = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Assert-PrivacyPrestate.ps1') -Raw
            $applySource = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Set-PrivacyRegistryTargets.ps1') -Raw
            $verifySource = Get-Content (Join-Path $repo 'Modules/Privacy/Test-PrivacyCompliance.ps1') -Raw
            $restoreSource = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Restore-PrivacyRegistryState.ps1') -Raw
            $rollbackSource = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $backupSource | Should -Match 'SchemaVersion = 7'
            $backupSource | Should -Match 'WeatherWidgetRemovalSelected'
            $backupSource | Should -Match 'AppxFirewallState = \$appxFirewallState'
            $backupSource | Should -Match 'Get-PrivacyAppxFirewallState -PackageFamilyNames \$appxFirewallFamilies'
            $applySource | Should -Match 'SchemaVersion -ne 7'
            $applySource | Should -Match 'requires a decision-bound schema-7 snapshot'
            $verifySource | Should -Match 'SchemaVersion -ne 7'
            $verifySource | Should -Match 'requires a schema-7 Apply snapshot'
            $restoreSource | Should -Match 'SchemaVersion -notin @\(2, 3, 4, 5, 6, 7\)'
            $restoreSource | Should -Match 'Restore-PrivacyAppxFirewallState -State \$snapshot.AppxFirewallState -Scope All'
            $backupSource | Should -Match "Register-Backup -Type 'Privacy' -Data \`$tier1Inventory -Name 'Privacy_Tier1AppInventory'"
            $prestateSource | Should -Match 'Privacy Tier 1 decision/artifact mismatch'
            $prestateSource | Should -Match 'Tier 1 package/provisioning inventory drifted before Apply'
            $rollbackSource | Should -Match "eq 'Privacy_Tier1AppInventory'"
            $rollbackSource | Should -Match 'schema-5/6/7 Tier 1 decision requires a schema-1 tier1-policy app inventory'
            $rollbackSource | Should -Match '\[Array\]::Sort\(\$sealedFamilies, \[StringComparer\]::Ordinal\)'

            InModuleScope Privacy {
                $catalog = Get-PrivacyTier1AppCatalog
                @($catalog.Apps).Count | Should -Be 8
                @($catalog.Apps.AppName | Sort-Object -Unique).Count | Should -Be 8
                $entries = @($catalog.Apps | ForEach-Object {
                        [PSCustomObject]@{
                            AppName = [string]$_.AppName; Present = $false
                            PackageFullName = $null; PackageFamilyName = $null; Version = $null
                            ProvisionedPackageNames = @(); StoreId = [string]$_.StoreId
                            ExpectedPackageNames = @($_.ExpectedPackageNames)
                        }
                    })
                $inventory = [PSCustomObject]@{
                    SchemaVersion = 1; Mode = 'tier1-policy'
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                    PolicySha256 = [string]$catalog.PolicySha256
                    CatalogSha256 = [string]$catalog.CatalogSha256
                    InventorySha256 = Get-PrivacyBloatwareInventoryFingerprint -Entries $entries
                    Entries = $entries
                }
                (Assert-PrivacyTier1AppInventory -Inventory $inventory) | Should -BeTrue
                $inventory.PolicySha256 = ('0' * 64)
                { Assert-PrivacyTier1AppInventory -Inventory $inventory } | Should -Throw '*different policy or Store catalog*'

                $preCopilotCatalog = Get-PrivacyTier1AppCatalog -PreCopilot
                $preCopilotEntries = @($preCopilotCatalog.Apps | ForEach-Object {
                        [PSCustomObject]@{
                            AppName = [string]$_.AppName; Present = $false
                            PackageFullName = $null; PackageFamilyName = $null; Version = $null
                            ProvisionedPackageNames = @(); StoreId = [string]$_.StoreId
                            ExpectedPackageNames = @($_.ExpectedPackageNames)
                        }
                    })
                $preCopilotInventory = [PSCustomObject]@{
                    SchemaVersion = 1; Mode = 'tier1-policy'
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                    PolicySha256 = [string]$preCopilotCatalog.PolicySha256
                    CatalogSha256 = [string]$preCopilotCatalog.CatalogSha256
                    InventorySha256 = Get-PrivacyBloatwareInventoryFingerprint -Entries $preCopilotEntries
                    Entries = $preCopilotEntries
                }
                (Assert-PrivacyTier1AppInventory -Inventory $preCopilotInventory) | Should -BeTrue

                $legacyCatalog = Get-PrivacyTier1AppCatalog -LegacyV225
                $legacyEntries = @($legacyCatalog.Apps | ForEach-Object {
                        [PSCustomObject]@{
                            AppName = [string]$_.AppName; Present = $false
                            PackageFullName = $null; PackageFamilyName = $null; Version = $null
                            ProvisionedPackageNames = @(); StoreId = [string]$_.StoreId
                            ExpectedPackageNames = @($_.ExpectedPackageNames)
                        }
                    })
                $legacyInventory = [PSCustomObject]@{
                    SchemaVersion = 1; Mode = 'tier1-policy'
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                    PolicySha256 = [string]$legacyCatalog.PolicySha256
                    CatalogSha256 = [string]$legacyCatalog.CatalogSha256
                    InventorySha256 = Get-PrivacyBloatwareInventoryFingerprint -Entries $legacyEntries
                    Entries = $legacyEntries
                }
                (Assert-PrivacyTier1AppInventory -Inventory $legacyInventory) | Should -BeTrue
            }
        }

        It "Should hash strict AppX firewall state and restore only other-user collateral during Apply" {
            InModuleScope Privacy {
                $family = 'Test.BundleApp_testpub'
                $otherSid = 'S-1-5-21-1-2-3-1000'
                $targetSid = 'S-1-5-21-1-2-3-1001'
                $otherEntry = [PSCustomObject]@{
                    Name='Test.BundleApp-Other';Type='String'
                    Data="v2.33|Action=Allow|PFN=$family|LUOwn=$otherSid|"
                }
                $targetEntry = [PSCustomObject]@{
                    Name='Test.BundleApp-Target';Type='String'
                    Data="v2.33|Action=Allow|PFN=$family|LUOwn=$targetSid|"
                }
                $state = [PSCustomObject]@{
                    SchemaVersion=1;RegistryPath=$script:PrivacyAppxFirewallRegistryPath;KeyExisted=$true
                    PackageFamilyNames=@($family);EntryCount=2;Entries=@($otherEntry,$targetEntry);StateSha256=''
                }
                $state.StateSha256 = Get-PrivacyAppxFirewallStateHash -State $state
                (Assert-PrivacyAppxFirewallState -State $state -ExpectedPackageFamilyNames @($family)) |
                    Should -BeTrue
                $tampered = $state | ConvertTo-Json -Depth 8 | ConvertFrom-Json
                $tampered.Entries[0].Data += 'tampered'
                { Assert-PrivacyAppxFirewallState -State $tampered } | Should -Throw '*hash does not match*'

                $current = [PSCustomObject]@{
                    SchemaVersion=1;RegistryPath=$script:PrivacyAppxFirewallRegistryPath;KeyExisted=$true
                    PackageFamilyNames=@($family);EntryCount=1;Entries=@($targetEntry);StateSha256=''
                }
                $current.StateSha256 = Get-PrivacyAppxFirewallStateHash -State $current
                $script:firewallStateRead = 0
                Mock Get-PrivacyAppxFirewallState {
                    $script:firewallStateRead++
                    if ($script:firewallStateRead -eq 1) { $current } else { $state }
                }
                Mock Test-Path { $true }
                Mock New-ItemProperty {}
                Mock Remove-ItemProperty {}

                $restored = Restore-PrivacyAppxFirewallState -State $state `
                    -Scope OtherUsers -TargetUserSid $targetSid
                $restored.Success | Should -BeTrue
                $restored.Restored | Should -Be 1
                $restored.Removed | Should -Be 0
                $restored.Verified | Should -Be 1
                Should -Invoke New-ItemProperty -Times 1 -Exactly -ParameterFilter {
                    [string]$Name -ceq 'Test.BundleApp-Other' -and
                    [string]$Value -ceq [string]$otherEntry.Data -and
                    [string]$PropertyType -ceq 'String'
                }
                Should -Invoke Remove-ItemProperty -Times 0 -Exactly
            }
        }

        It "Should avoid enumerating unrelated firewall values when Tier 2 has no sealed families" {
            InModuleScope Privacy {
                Mock Test-Path { $true }
                Mock Get-Item { throw 'unrelated firewall values must not be read' }

                $state = Get-PrivacyAppxFirewallState -PackageFamilyNames @()
                $state.KeyExisted | Should -BeTrue
                @($state.PackageFamilyNames).Count | Should -Be 0
                $state.EntryCount | Should -Be 0
                @($state.Entries).Count | Should -Be 0
                (Assert-PrivacyAppxFirewallState -State $state -ExpectedPackageFamilyNames @()) |
                    Should -BeTrue
                Should -Invoke Get-Item -Times 0 -Exactly
            }
        }

        It "Should preserve an absent firewall key only when its sealed entry set is empty" {
            InModuleScope Privacy {
                Mock Test-Path { $false }
                Mock Get-Item { throw 'an absent firewall key must not be opened' }
                Mock New-Item { throw 'an absent empty prestate must not create the key' }

                $state = Get-PrivacyAppxFirewallState -PackageFamilyNames @()
                $state.KeyExisted | Should -BeFalse
                $state.EntryCount | Should -Be 0
                (Assert-PrivacyAppxFirewallState -State $state -ExpectedPackageFamilyNames @()) |
                    Should -BeTrue

                $restored = Restore-PrivacyAppxFirewallState -State $state -Scope All
                $restored.Success | Should -BeTrue
                $restored.Restored | Should -Be 0
                $restored.Removed | Should -Be 0
                $restored.Verified | Should -Be 0
                Should -Invoke Get-Item -Times 0 -Exactly
                Should -Invoke New-Item -Times 0 -Exactly

                $family = 'Test.BundleApp_testpub'
                $invalid = [PSCustomObject]@{
                    SchemaVersion=1;RegistryPath=$script:PrivacyAppxFirewallRegistryPath;KeyExisted=$false
                    PackageFamilyNames=@($family);EntryCount=1
                    Entries=@([PSCustomObject]@{
                            Name='Test.BundleApp-Rule';Type='String'
                            Data="v2.33|Action=Allow|PFN=$family|"
                        })
                    StateSha256=''
                }
                $invalid.StateSha256 = Get-PrivacyAppxFirewallStateHash -State $invalid
                { Assert-PrivacyAppxFirewallState -State $invalid } |
                    Should -Throw '*invalid entry/key count*'
            }
        }

        It "Should bind Tier 2 to the second pre-Apply gate" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $prestate = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Assert-PrivacyPrestate.ps1') -Raw
            $prestate | Should -Match 'Tier 2 decision/artifact mismatch'
            $prestate | Should -Match 'InventorySha256'
            $prestate | Should -Match 'drifted before Apply'
            $rollback = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $rollback | Should -Match 'expectedBloatwareSchema = if \(\[int\]\$privacyPreState\.SchemaVersion -in @\(6, 7\)\) \{ 3 \} else \{ 2 \}'
            $rollback | Should -Match 'Tier 2 decision requires a catalog-bound schema-\$expectedBloatwareSchema action inventory'
        }

        It "Should skip the Tier 2 action log in the restore engine by design, without failing the session" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $rollback = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $rollback | Should -Match "eq 'Privacy_BloatwareActions'"
            $rollback | Should -Match 'skipped by design'
            $rollback | Should -Match 'skipped by design as exact state'
            $rollback | Should -Match 'Best-effort local package re-registration with verified Store fallback[\s\S]{0,180}Restore-BloatwareApps -SessionPath'
        }

        It "Should offer the best-effort reinstall from canonical Restore-Session, default No, without touching the exact-restore verdict" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $rollback = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $rollback | Should -Match 'function Invoke-RestoreBloatwareReinstallOffer'
            $rollback | Should -Match "eq 'Privacy_BloatwareActions'"
            $rollback | Should -Match 'Get-BloatwareRestoreAssessment -SessionPath \$SessionPath'
            $rollback | Should -Match "Status -eq 'NothingToDo'"
            $rollback | Should -Match 'Attempt the best-effort app recovery now\?[\s\S]{0,900}Your choice \[Y/N\] \(default: N\)'
            $rollback | Should -Match 'Restore-BloatwareApps -SessionPath \$SessionPath -Confirm:\$false'
            $rollback | Should -Match 'Invoke-RestoreBloatwareReinstallOffer[\s\S]{0,500}Invoke-RestoreRebootPrompt'
        }

        It "Should validate the sealed session, require the original user, and verify reinstall registration" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $restoreSource = Get-Content (Join-Path $repo 'Modules/Privacy/Public/Restore-BloatwareApps.ps1') -Raw
            $assessmentSource = Get-Content (Join-Path $repo 'Modules/Privacy/Public/Get-BloatwareRestoreAssessment.ps1') -Raw
            $userContextSource = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Get-PrivacyUserContext.ps1') -Raw
            $assessmentSource | Should -Match 'Assert-SessionManifest'
            $assessmentSource | Should -Match 'Get-SessionRestoreReceipt'
            $assessmentSource.IndexOf(". (Join-Path `$repoRoot 'Core\QuickActions.ps1')") |
                Should -BeLessThan $assessmentSource.IndexOf(". (Join-Path `$repoRoot 'Core\Rollback.ps1')")
            $assessmentSource | Should -Match 'Get-PrivacyCurrentProcessUserSid'
            $userContextSource | Should -Match 'WindowsIdentity\]::GetCurrent\(\)\.User\.Value'
            $assessmentSource | Should -Match "Status = 'OriginalUserRequired'"
            $assessmentSource | Should -Match 'Get-AppxPackage -Name \$_ -ErrorAction Stop'
            $restoreSource | Should -Match 'Get-BloatwareRestoreAssessment -SessionPath \$SessionPath'
            # IndexOf returns -1 for something that is gone, and -1 is less than
            # any real index, so this ordering assertion passed when the logger
            # dot-source it exists to guarantee was deleted outright.
            $loggerIndex = $restoreSource.IndexOf(". (Join-Path `$repoRoot 'Core\Logger.ps1')")
            $assessmentIndex = $restoreSource.IndexOf('Get-BloatwareRestoreAssessment -SessionPath $SessionPath')
            $loggerIndex | Should -BeGreaterThan -1 -Because 'the restore worker must dot-source the logger at all'
            $assessmentIndex | Should -BeGreaterThan -1
            $loggerIndex | Should -BeLessThan $assessmentIndex
            $restoreSource | Should -Match 'Add-AppxPackage -RegisterByFamilyName'
            $restoreSource | Should -Match 're-registered and verified from sealed package family'
            $restoreSource | Should -Match "'source','update','--name','msstore'"
            $restoreSource | Should -Match "'install','--id',\`$storeId,'--exact','--source','msstore'"
            $restoreSource | Should -Match "ArgumentList @\('--version'\) -TimeoutSeconds 15"
            $restoreSource | Should -Match "'source','update','--name','msstore','--disable-interactivity'[\s\S]{0,100}-TimeoutSeconds 120"
            $restoreSource | Should -Match "'install','--id',\`$storeId,'--exact','--source','msstore'[\s\S]{0,220}-TimeoutSeconds 600"
            $restoreSource | Should -Match 'Get-Command winget -CommandType Application'
            $restoreSource | Should -Match 'taskkill\.exe'
            $restoreSource | Should -Match '\$killer\.WaitForExit\(5000\)'
            $restoreSource | Should -Match '\$process\.WaitForExit\(2000\)'
            $restoreSource | Should -Match '\[Diagnostics\.Process\]::new\(\)'
            $restoreSource | Should -Match 'RedirectStandardOutput = \$true'
            $restoreSource | Should -Match 'RedirectStandardError = \$true'
            $restoreSource | Should -Not -Match 'Start-Process'
            $restoreSource | Should -Match 'winget startup probe failed with exit code'
            $restoreSource | Should -Match '\$result\.Success = \(\$result\.Failed -eq 0 -and \$result\.Skipped -eq 0\)'
            $restoreSource | Should -Not -Match '\$result\.Success = \$true[\s\S]{0,80}winget is unavailable'
            $restoreSource | Should -Not -Match 'Get-AppxPackage -Name \$_ -User'
        }

        It "Should return the real exit code from the bounded recovery process helper" {
            InModuleScope Privacy {
                $exitCode = Invoke-PrivacyBoundedProcess -FilePath $env:ComSpec `
                    -ArgumentList @('/d', '/c', 'exit', '7') -TimeoutSeconds 15
                $exitCode | Should -Be 7
            }
        }

        It "Should reject process arguments that would require command-line quoting" {
            InModuleScope Privacy {
                {
                    Invoke-PrivacyBoundedProcess -FilePath $env:ComSpec `
                        -ArgumentList @('/d', '/c', 'exit 7') -TimeoutSeconds 15
                } | Should -Throw '*refused an unsupported process argument*'
            }
        }

        It "Should terminate a recovery process at its wall-clock deadline" {
            InModuleScope Privacy {
                $batchPath = Join-Path (Join-Path $env:SystemRoot 'Temp') `
                    'NoIDPrivacy-RecoveryTimeout-Test.cmd'
                if (Test-Path -LiteralPath $batchPath) {
                    throw "Refusing to replace test process script: $batchPath"
                }
                try {
                    [IO.File]::WriteAllText(
                        $batchPath,
                        '@powershell.exe -NoLogo -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 30"',
                        [Text.Encoding]::ASCII
                    )
                    $watch = [Diagnostics.Stopwatch]::StartNew()
                    {
                        Invoke-PrivacyBoundedProcess -FilePath $env:ComSpec `
                            -ArgumentList @('/d', '/c', $batchPath) -TimeoutSeconds 1
                    } | Should -Throw '*timed out after 1 seconds*'
                    $watch.Stop()
                    # The helper owns a 1-second process deadline followed by
                    # bounded 5-second tree termination and 2-second parent
                    # cleanup waits. Allow scheduling headroom on loaded VMs,
                    # while staying below the unbounded 30-second positive
                    # control so a lost process-tree kill still fails.
                    $watch.Elapsed.TotalSeconds | Should -BeLessThan 25
                }
                finally {
                    Remove-Item -LiteralPath $batchPath -Force -ErrorAction SilentlyContinue
                }
            }
        }

        It "Should assess every locally registerable original app and return NothingToDo for an empty original inventory" {
            $sessionRoot = Join-Path $TestDrive 'Session_20260718_120000_000_assessment'
            $null = New-Item -Path (Join-Path $sessionRoot 'Privacy') -ItemType Directory -Force

            InModuleScope Privacy -Parameters @{ SessionRoot = $sessionRoot } {
                param($SessionRoot)

                $config = Get-PrivacyBloatwareConfig
                $mappedNames = @($config.RemoveApps | Where-Object {
                        -not [string]::IsNullOrWhiteSpace([string]$config.Mappings.$_.StoreId)
                    })
                $unmappedName = @($config.RemoveApps | Where-Object {
                        [string]::IsNullOrWhiteSpace([string]$config.Mappings.$_.StoreId)
                    })[0]
                $existingName = $mappedNames[0]
                $missingName = $mappedNames[1]
                $presentNames = @($existingName, $missingName, $unmappedName)
                $currentSid = 'S-1-5-21-100-200-300-1001'
                $script:AssessmentCurrentSid = $currentSid
                Mock Get-PrivacyCurrentProcessUserSid { $script:AssessmentCurrentSid }

                function Get-AssessmentActionLog([string[]]$PresentNames) {
                    $entries = @($config.RemoveApps | ForEach-Object {
                            $appName = [string]$_
                            $mapping = $config.Mappings.$appName
                            $present = $appName -in $PresentNames
                            [PSCustomObject]@{
                                AppName = $appName
                                Present = $present
                                PackageFullName = if ($present) { "$appName`_1.0.0.0_x64__test" } else { $null }
                                PackageFamilyName = if ($present) { "$appName`_test" } else { $null }
                                Version = if ($present) { '1.0.0.0' } else { $null }
                                ProvisionedPackageNames = @()
                                StoreId = [string]$mapping.StoreId
                                ExpectedPackageNames = @($mapping.ExpectedPackageNames)
                            }
                    })
                    [PSCustomObject]@{
                        SchemaVersion = 3
                        Mode = 'standard'
                        WeatherWidgetRemovalSelected = $false
                        InteractiveUserSid = $currentSid
                        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                        CatalogSha256 = [string]$config.CatalogSha256
                        InventorySha256 = Get-PrivacyBloatwareInventoryFingerprint -Entries $entries
                        Entries = $entries
                    }
                }

                $script:AssessmentLogPath = Join-Path $SessionRoot 'Privacy\Privacy_BloatwareActions.json'
                $script:AssessmentManifest = [PSCustomObject]@{
                    modules = @([PSCustomObject]@{
                            name = 'Privacy'
                            artifacts = @([PSCustomObject]@{
                                    type = 'Privacy'
                                    name = 'Privacy_BloatwareActions'
                                    relativePath = 'Privacy/Privacy_BloatwareActions.json'
                                })
                        })
                }
                if (-not (Get-Command Get-SessionManifest -ErrorAction SilentlyContinue)) {
                    function Get-SessionManifest { param([string]$SessionPath) $null = $SessionPath }
                }
                if (-not (Get-Command Assert-SessionManifest -ErrorAction SilentlyContinue)) {
                    function Assert-SessionManifest { param($SessionPath, $Manifest, $RequestedModules) $null = $SessionPath, $Manifest, $RequestedModules }
                }
                if (-not (Get-Command Resolve-SessionChildPath -ErrorAction SilentlyContinue)) {
                    function Resolve-SessionChildPath { param($SessionPath, $RelativePath) $null = $SessionPath, $RelativePath }
                }
                Mock Get-SessionManifest { $script:AssessmentManifest }
                Mock Assert-SessionManifest { }
                Mock Resolve-SessionChildPath { $script:AssessmentLogPath }
                $script:ExistingExpectedName = [string]$config.Mappings.$existingName.ExpectedPackageNames[0]
                Mock Get-AppxPackage {
                    param($Name)
                    if ([string]$Name -ceq $script:ExistingExpectedName) {
                        [PSCustomObject]@{ Name = $Name }
                    }
                }

                Get-AssessmentActionLog -PresentNames $presentNames |
                    ConvertTo-Json -Depth 10 |
                    Set-Content -LiteralPath $script:AssessmentLogPath -Encoding UTF8
                $needed = Get-BloatwareRestoreAssessment -SessionPath $SessionRoot
                $needed.Success | Should -BeTrue -Because $needed.Error
                $needed.Status | Should -Be 'Needed'
                $needed.RecordedPresent | Should -Be 3
                $needed.Mapped | Should -Be 3
                $needed.LocalRegisterable | Should -Be 3
                $needed.StoreMapped | Should -Be 2
                $needed.Missing | Should -Be 2
                $needed.AlreadyPresent | Should -Be 1
                $needed.Unmapped | Should -Be 0

                Get-AssessmentActionLog -PresentNames @() |
                    ConvertTo-Json -Depth 10 |
                    Set-Content -LiteralPath $script:AssessmentLogPath -Encoding UTF8
                $nothing = Get-BloatwareRestoreAssessment -SessionPath $SessionRoot
                $nothing.Success | Should -BeTrue -Because $nothing.Error
                $nothing.Status | Should -Be 'NothingToDo'
                $nothing.RecordedPresent | Should -Be 0
                $nothing.Missing | Should -Be 0
            }
        }

        It "Should read a v3.3 Bing News inventory without reviving its withdrawn Store fallback" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $assessmentSource = Get-Content (Join-Path $repo 'Modules/Privacy/Public/Get-BloatwareRestoreAssessment.ps1') -Raw
            $assessmentSource | Should -Match 'currentRecoveryConfig = Get-PrivacyBloatwareConfig'
            $assessmentSource | Should -Match 'currentMapping\.StoreId -ceq \[string\]\$storeIds\[0\]'

            InModuleScope Privacy {
                $current = Get-PrivacyBloatwareConfig
                $previous = Get-PrivacyBloatwareConfig -PreviousV33
                [string]$previous.Mappings.'Microsoft.BingNews'.StoreId | Should -BeExactly '9WZDNCRFHVFW'
                [string]$current.Mappings.'Microsoft.BingNews'.StoreId | Should -BeExactly ''
                @($current.Mappings.'Microsoft.BingNews'.ExpectedPackageNames).Count | Should -Be 0
            }
        }

        It "Should report Tier 2 actions as informational and never fold them into BAVR Verified/Failed totals" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $complianceSource = Get-Content (Join-Path $repo 'Modules/Privacy/Test-PrivacyCompliance.ps1') -Raw
            $complianceSource | Should -Match "Status -notin @\('NotApplicable', 'NotChecked', 'Informational'\)"
            $complianceSource | Should -Match "Status = 'Informational'"
            $invoke = Get-Content (Join-Path $repo 'Modules/Privacy/Public/Invoke-PrivacyHardening.ps1') -Raw
            $invoke | Should -Match 'BloatwareActions\s*=\s*\$bloatwareActionResult'
            $invoke | Should -Match '\$results \+= \[bool\]\$bloatwareActionResult\.Success'
        }
    }

    Context "Exact registry BAVR" {
        It "Should ship exact target backup and restore helpers" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            foreach ($name in @(
                    'Get-PrivacyRegistryTargets.ps1', 'Get-PrivacyUserContext.ps1',
                    'PrivacyAppxFirewall.ps1', 'PrivacyUserAppx.ps1',
                    'Get-PrivacyUcpdProtectionState.ps1',
                    'Assert-PrivacyRegistrySnapshot.ps1', 'Assert-PrivacyPrestate.ps1',
                    'PrivacyWindowsSearch.ps1',
                    'PrivacySearchPolicyNotification.ps1',
                    'Set-PrivacyRegistryTargets.ps1', 'Restore-PrivacyRegistryState.ps1'
                )) {
                (Join-Path $repo "Modules/Privacy/Private/$name") | Should -Exist
            }
        }

        It 'Should refresh the effective Windows Search surface through documented setting-change notifications' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $helper = Get-Content (Join-Path $repo 'Modules/Privacy/Private/PrivacySearchPolicyNotification.ps1') -Raw
            $windowsSearch = Get-Content (Join-Path $repo 'Modules/Privacy/Private/PrivacyWindowsSearch.ps1') -Raw
            $apply = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Set-PrivacyRegistryTargets.ps1') -Raw
            $restore = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Restore-PrivacyRegistryState.ps1') -Raw
            $compliance = Get-Content (Join-Path $repo 'Modules/Privacy/Test-PrivacyCompliance.ps1') -Raw
            $completeVerifier = Get-Content (Join-Path $repo 'Tools/Verify-Complete-Hardening.ps1') -Raw

            $helper | Should -Match 'SendMessageTimeout'
            $helper | Should -Match "'Policy'"
            $helper | Should -Match "'Search'"
            $helper | Should -Match "'SearchSettings'"
            $helper | Should -Match "'WebSearchProviders'"
            $helper | Should -Match '\[IntPtr\]0xffff'
            $processKillPattern = '(?im)^\s*(?:Stop-Process|taskkill(?:\.exe)?)\b'
            'Stop-Process -Name SearchHost' | Should -Match $processKillPattern
            $helper | Should -Not -Match $processKillPattern
            $apply | Should -Match 'Send-PrivacySearchPolicyChangeNotification -Entries @\(\$Snapshot\.Entries\)'
            $restore | Should -Match 'Send-PrivacySearchPolicyChangeNotification -Entries \$entries'

            # The documented Microsoft API is executed in the original
            # Explorer user's limited token. Apply/Verify/Restore all consume
            # that same effective state without adding a second report target.
            $windowsSearch | Should -Match 'Get-WindowsSearchSetting'
            $windowsSearch | Should -Match 'Set-WindowsSearchSetting'
            $windowsSearch | Should -Match 'New-ScheduledTaskPrincipal[\s\S]+-LogonType Interactive -RunLevel Limited'
            $windowsSearch | Should -Match 'WindowsSearch worker identity mismatch'
            $windowsSearch | Should -Match 'The native WindowsSearch refresh changed registry state outside the pre-applied BAVR target'
            $windowsSearch | Should -Match 'The native WindowsSearch refresh changed an unrelated Search API setting'
            $apply | Should -Match 'Invoke-PrivacyWindowsSearchUserState[\s\S]+-Operation RefreshWebResults[\s\S]+-WebResultsEnabled:\$false'
            $restore | Should -Match 'Invoke-PrivacyWindowsSearchUserState[\s\S]+-Operation RefreshWebResults'
            $compliance | Should -Match 'EnableWebResultsSetting=False'
            $completeVerifier | Should -Match 'EnableWebResultsSetting=False'

            InModuleScope Privacy {
                (Test-PrivacySearchPolicyNotificationRequired -Entries @(
                        [PSCustomObject]@{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' }
                    )) | Should -BeTrue
                (Test-PrivacySearchPolicyNotificationRequired -Entries @(
                        [PSCustomObject]@{ Path='HKU:\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\SearchSettings\WebSearchProviders' }
                    )) | Should -BeTrue
                (Test-PrivacySearchPolicyNotificationRequired -Entries @(
                        [PSCustomObject]@{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' }
                    )) | Should -BeFalse

                $areas = @(Get-PrivacySearchSettingNotificationAreas -Entries @(
                        [PSCustomObject]@{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' },
                        [PSCustomObject]@{ Path='HKU:\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Search' },
                        [PSCustomObject]@{ Path='HKU:\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\SearchSettings' },
                        [PSCustomObject]@{ Path='HKU:\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\SearchSettings\WebSearchProviders' }
                    ))
                ($areas -join '|') | Should -Be 'Policy|Search|SearchSettings|WebSearchProviders'
                @(Get-PrivacySearchSettingNotificationAreas -Entries @(
                        [PSCustomObject]@{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' }
                    )).Count | Should -Be 0

                Mock Get-WindowsSearchSetting {
                    @(
                        [PSCustomObject]@{ Setting='EnableWebResultsSetting'; Value='False' }
                        [PSCustomObject]@{ Setting='SafeSearchSetting'; Value='Strict' }
                    )
                }
                $state = Get-PrivacyWindowsSearchApiState
                $state.WebResultsEnabled | Should -BeFalse
                @($state.Settings).Count | Should -Be 2
                [string]$state.Settings[0].Setting | Should -BeExactly 'EnableWebResultsSetting'
                (Test-PrivacyWindowsSearchExactState -Expected $state.Settings -Actual $state.Settings) |
                    Should -BeTrue
            }
        }

        It 'Should reject ambiguous or non-Boolean effective Windows Search state' {
            InModuleScope Privacy {
                Mock Get-WindowsSearchSetting {
                    @(
                        [PSCustomObject]@{ Setting='EnableWebResultsSetting'; Value='False' }
                        [PSCustomObject]@{ Setting='EnableWebResultsSetting'; Value='False' }
                    )
                }
                { Get-PrivacyWindowsSearchApiState } | Should -Throw '*invalid or duplicate*'

                Mock Get-WindowsSearchSetting {
                    [PSCustomObject]@{ Setting='EnableWebResultsSetting'; Value='Disabled' }
                }
                { Get-PrivacyWindowsSearchApiState } | Should -Throw '*one Boolean EnableWebResultsSetting*'
            }
        }

        It 'Should accept only a complete decision-bound schema-3 snapshot' {
            InModuleScope Privacy {
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 3; Mode = 'MSRecommended'
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    EditionFamily = 'Professional'; BuildNumber = 26100; DeclaredRegistryTargetCount = 1
                    NotApplicableRegistryTargets = @()
                    TargetCount = 1
                    DeclaredServiceNames = @(); ApplicableServiceNames = @()
                    DeclaredScheduledTaskPaths = @(); ApplicableScheduledTaskPaths = @()
                    Entries = @([PSCustomObject]@{
                            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                            Name = 'AllowTelemetry'; ApplyType = 'DWord'; ApplyValue = 1
                            KeyExisted = $false; Exists = $false; Type = $null; Value = $null
                        })
                }
                (Assert-PrivacyRegistrySnapshot -Snapshot $snapshot) | Should -BeTrue

                $snapshot.Entries[0].ApplyType = 'dword'
                { Assert-PrivacyRegistrySnapshot -Snapshot $snapshot } |
                    Should -Throw '*invalid Apply type/value*'
                $snapshot.Entries[0].ApplyType = 'DWord'

                $snapshot.Entries[0].Type = 'DWord'
                { Assert-PrivacyRegistrySnapshot -Snapshot $snapshot } | Should -Throw '*absent value must have null*'
            }
        }

        It 'seals and validates the ancestor levels Apply creates implicitly' {
            InModuleScope Privacy {
                # Restore used to visit only entry paths, so ...\Windows\Appx -
                # created implicitly by New-Item -Force for a deeper target key -
                # survived an "exact" restore as an empty NoID-made policy key.
                # The inventory is additive and presence-gated on schema 7.
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 3; Mode = 'MSRecommended'
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    EditionFamily = 'Professional'; BuildNumber = 26100; DeclaredRegistryTargetCount = 1
                    NotApplicableRegistryTargets = @()
                    TargetCount = 1
                    DeclaredServiceNames = @(); ApplicableServiceNames = @()
                    DeclaredScheduledTaskPaths = @(); ApplicableScheduledTaskPaths = @()
                    AbsentAncestorKeys = @('HKLM:\SOFTWARE\Policies\Microsoft\Windows')
                    Entries = @([PSCustomObject]@{
                            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                            Name = 'AllowTelemetry'; ApplyType = 'DWord'; ApplyValue = 1
                            KeyExisted = $false; Exists = $false; Type = $null; Value = $null
                        })
                }
                (Assert-PrivacyRegistrySnapshot -Snapshot $snapshot) | Should -BeTrue

                # An ancestor that owns no declared target is corrupt inventory:
                # deleting it on restore would touch state this run never created.
                $snapshot.AbsentAncestorKeys = @('HKLM:\SOFTWARE\Policies\Microsoft\Edge')
                { Assert-PrivacyRegistrySnapshot -Snapshot $snapshot } |
                    Should -Throw '*owns no declared target*'

                # Duplicates and paths outside the machine/user policy areas are refused.
                $snapshot.AbsentAncestorKeys = @(
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows',
                    'hklm:\software\policies\microsoft\windows'
                )
                { Assert-PrivacyRegistrySnapshot -Snapshot $snapshot } |
                    Should -Throw '*Invalid or duplicate Privacy absent ancestor*'
                $snapshot.AbsentAncestorKeys = @('HKLM:\SYSTEM\CurrentControlSet\Services')
                { Assert-PrivacyRegistrySnapshot -Snapshot $snapshot } |
                    Should -Throw '*Invalid or duplicate Privacy absent ancestor*'

                # A snapshot without the property keeps its previous semantics.
                $legacy = [PSCustomObject]@{
                    SchemaVersion = 3; Mode = 'MSRecommended'
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    EditionFamily = 'Professional'; BuildNumber = 26100; DeclaredRegistryTargetCount = 1
                    NotApplicableRegistryTargets = @()
                    TargetCount = 1
                    DeclaredServiceNames = @(); ApplicableServiceNames = @()
                    DeclaredScheduledTaskPaths = @(); ApplicableScheduledTaskPaths = @()
                    Entries = @([PSCustomObject]@{
                            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                            Name = 'AllowTelemetry'; ApplyType = 'DWord'; ApplyValue = 1
                            KeyExisted = $false; Exists = $false; Type = $null; Value = $null
                        })
                }
                (Assert-PrivacyRegistrySnapshot -Snapshot $legacy) | Should -BeTrue
            }
        }

        It 'Should reject duplicate targets and applicability outside the declared runtime inventory' {
            InModuleScope Privacy {
                $entry = [PSCustomObject]@{
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                    Name = 'AllowTelemetry'; ApplyType = 'DWord'; ApplyValue = 1
                    KeyExisted = $true; Exists = $true; Type = 'DWord'; Value = 3
                }
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 3; Mode = 'Strict'; InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                    EditionFamily = 'Professional'; BuildNumber = 26100; DeclaredRegistryTargetCount = 2
                    NotApplicableRegistryTargets = @()
                    TargetCount = 2; Entries = @($entry, $entry.PSObject.Copy())
                    DeclaredServiceNames = @('DiagTrack'); ApplicableServiceNames = @('UnknownService')
                    DeclaredScheduledTaskPaths = @(); ApplicableScheduledTaskPaths = @()
                }
                { Assert-PrivacyRegistrySnapshot -Snapshot $snapshot } | Should -Throw
            }
        }

        It 'Should bind the snapshot Apply contract to the selected target set' {
            InModuleScope Privacy {
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 3; Mode = 'MSRecommended'
                    InteractiveUserSid = 'S-1-5-21-1-2-3-1001'; TargetCount = 1
                    EditionFamily = 'Professional'; BuildNumber = 26100; DeclaredRegistryTargetCount = 1
                    NotApplicableRegistryTargets = @()
                    DeclaredServiceNames = @(); ApplicableServiceNames = @()
                    DeclaredScheduledTaskPaths = @(); ApplicableScheduledTaskPaths = @()
                    Entries = @([PSCustomObject]@{
                            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                            Name = 'AllowTelemetry'; ApplyType = 'DWord'; ApplyValue = 1
                            KeyExisted = $true; Exists = $true; Type = 'DWord'; Value = 3
                        })
                }
                $wrongPlan = @([PSCustomObject]@{
                        Path = $snapshot.Entries[0].Path; Name = $snapshot.Entries[0].Name
                        Type = 'DWord'; Value = 0
                    })
                { Assert-PrivacyRegistrySnapshot -Snapshot $snapshot -ExpectedTargets $wrongPlan } |
                    Should -Throw '*Apply contract mismatch*'
            }
        }

        It 'Should accept complete current or legacy Tier 1 restore contracts and reject mixtures' {
            InModuleScope Privacy {
                function Get-Tier1SnapshotForTest {
                    param([object[]]$Targets)
                    $entries = @($Targets | ForEach-Object {
                            [PSCustomObject]@{
                                Path = [string]$_.Path; Name = [string]$_.Name
                                ApplyType = [string]$_.Type; ApplyValue = $_.Value
                                KeyExisted = $false; Exists = $false; Type = $null; Value = $null
                            }
                        })
                    return [PSCustomObject]@{
                        SchemaVersion = 6; Mode = 'MSRecommended'
                        InteractiveUserSid = 'S-1-5-21-1-2-3-1001'
                        EditionFamily = 'Enterprise'; BuildNumber = 26200
                        DomainJoined = $false; MdmRegistered = $false
                        ManagementStateKnown = $true; MultiSession = $false
                        Tier1PolicyRemovalSelected = $true
                        Tier2BloatwareRemovalSelected = $false
                        WeatherWidgetRemovalSelected = $false
                        DeclaredRegistryTargetCount = $entries.Count
                        NotApplicableRegistryTargets = @(); NotCheckedRegistryTargets = @()
                        TargetCount = $entries.Count; Entries = $entries
                        DeclaredServiceNames = @(); ApplicableServiceNames = @()
                        DeclaredScheduledTaskPaths = @(); ApplicableScheduledTaskPaths = @()
                    }
                }

                $currentTargets = @(Get-PrivacyTier1PolicyDefinition).Targets
                $legacyTargets = @(Get-PrivacyTier1LegacyV225PolicyDefinition).Targets
                $currentSnapshot = Get-Tier1SnapshotForTest -Targets $currentTargets
                $legacySnapshot = Get-Tier1SnapshotForTest -Targets $legacyTargets
                (Assert-PrivacyRegistrySnapshot -Snapshot $currentSnapshot) | Should -BeTrue
                (Assert-PrivacyRegistrySnapshot -Snapshot $legacySnapshot) | Should -BeTrue
                (Assert-PrivacyRegistrySnapshot -Snapshot $currentSnapshot -RestoreOnly) | Should -BeTrue
                (Assert-PrivacyRegistrySnapshot -Snapshot $legacySnapshot -RestoreOnly) | Should -BeTrue
                (Assert-PrivacyRegistrySnapshot -Snapshot $currentSnapshot -ExpectedTargets $currentTargets) | Should -BeTrue
                { Assert-PrivacyRegistrySnapshot -Snapshot $legacySnapshot -ExpectedTargets $currentTargets } |
                    Should -Throw '*missing selected Apply target*'

                $mixedTargets = @($legacyTargets | Select-Object -First 26)
                $mixedTargets += @($currentTargets | Where-Object Name -eq 'DynamicRemovalList')
                $mixedSnapshot = Get-Tier1SnapshotForTest -Targets $mixedTargets
                { Assert-PrivacyRegistrySnapshot -Snapshot $mixedSnapshot } |
                    Should -Throw '*current/legacy mixtures are invalid*'

                Mock Get-PrivacyTier1PolicyDefinition { throw 'current Apply inventory must not control restore' }
                Mock Get-PrivacyTier1LegacyV225PolicyDefinition { throw 'current helper file must not control restore' }
                (Assert-PrivacyRegistrySnapshot -Snapshot $currentSnapshot -RestoreOnly) | Should -BeTrue
                (Assert-PrivacyRegistrySnapshot -Snapshot $legacySnapshot -RestoreOnly) | Should -BeTrue
                { Assert-PrivacyRegistrySnapshot -Snapshot $currentSnapshot } |
                    Should -Throw '*current Apply inventory must not control restore*'
            }
        }

        It 'Should preserve an intentionally empty MultiString through Apply conversion' {
            InModuleScope Privacy {
                (Test-PrivacyRegistryValueMatch -Type MultiString `
                    -Expected ([string[]]@()) -Actual ([string[]]@())) | Should -BeTrue
                $script:CapturedPrivacyRegistryValue = 'not-called'
                $key = [PSCustomObject]@{}
                $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value {
                    param($Name)
                    if ($Name -ceq 'DynamicRemovalList') { 'MultiString' } else { 'DWord' }
                }
                $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                    param($Name,$Default,$Options)
                    $null=$Default,$Options
                    if ($Name -ceq 'DynamicRemovalList') { return ,([string[]]@()) }
                    return 0
                }
                Mock Assert-PrivacyRegistrySnapshot { $true }
                Mock Test-Path { $true }
                Mock Get-Item { $key }
                Mock Test-PrivacyRegistryValueMatch { $true }
                Mock Send-PrivacySearchPolicyChangeNotification { $true }
                Mock Get-PrivacyUserContext {
                    [PSCustomObject]@{ Sid='S-1-5-21-1-2-3-1001' }
                }
                Mock Invoke-PrivacyWindowsSearchUserState {
                    [PSCustomObject]@{
                        Success=$true; WebResultsEnabled=$false; RegistryStateUnchanged=$true
                    }
                }
                Mock New-ItemProperty {
                    param($LiteralPath,$Name,$PropertyType,$Value,$Force,$ErrorAction)
                    $null=$LiteralPath,$Name,$PropertyType,$Force,$ErrorAction
                    if ($Name -ceq 'DynamicRemovalList') {
                        $script:CapturedPrivacyRegistryValue = $Value
                    }
                }
                $snapshot = [PSCustomObject]@{
                    SchemaVersion=7; TargetCount=2; InteractiveUserSid='S-1-5-21-1-2-3-1001'
                    Entries=@(
                        [PSCustomObject]@{
                            Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages'
                            Name='DynamicRemovalList'; ApplyType='MultiString'; ApplyValue=[string[]]@()
                        }
                        [PSCustomObject]@{
                            Path='HKU:\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Search'
                            Name='BingSearchEnabled'; ApplyType='DWord'; ApplyValue=0
                        }
                    )
                }
                (Set-PrivacyRegistryTargets -Snapshot $snapshot -Confirm:$false) | Should -Be 2
                $script:CapturedPrivacyRegistryValue.GetType().FullName | Should -BeExactly 'System.String[]'
                @($script:CapturedPrivacyRegistryValue).Count | Should -Be 0
                Should -Invoke New-ItemProperty -Times 2 -Exactly
            }
        }

        It 'Should classify Home and Enterprise-only policy targets without registry-writability guesses' {
            InModuleScope Privacy {
                $homeContext = [PSCustomObject]@{
                    EditionFamily='Home'; WindowsManagedPolicySupported=$false; EnterprisePolicySupported=$false
                }
                $pro = [PSCustomObject]@{
                    EditionFamily='Professional'; WindowsManagedPolicySupported=$true; EnterprisePolicySupported=$false
                }
                $enterprise = [PSCustomObject]@{
                    EditionFamily='Enterprise'; WindowsManagedPolicySupported=$true; EnterprisePolicySupported=$true
                }
                (Get-PrivacyTargetApplicability `
                    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
                    -Name 'AllowTelemetry' -Applicability $homeContext).Applicable | Should -BeFalse
                (Get-PrivacyTargetApplicability `
                    -Path 'HKU:\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
                    -Name 'Start_IrisRecommendations' -Applicability $homeContext).Applicable | Should -BeTrue
                (Get-PrivacyTargetApplicability `
                    -Path 'HKU:\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Search' `
                    -Name 'BingSearchEnabled' -Applicability $homeContext).Applicable | Should -BeTrue
                (Get-PrivacyTargetApplicability `
                    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' `
                    -Name 'EnableSyncAdminReports' -Applicability $homeContext).Applicable | Should -BeTrue
                (Get-PrivacyTargetApplicability `
                    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' `
                    -Name 'DisableSoftLanding' -Applicability $pro).Applicable | Should -BeFalse
                (Get-PrivacyTargetApplicability `
                    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' `
                    -Name 'DisableSoftLanding' -Applicability $enterprise).Applicable | Should -BeTrue
            }
        }

        It 'Should fail closed for the UCPD-protected Widgets policy and seal the driver decision' {
            InModuleScope Privacy {
                $proProtected = [PSCustomObject]@{
                    EditionFamily='Professional'; WindowsManagedPolicySupported=$true; EnterprisePolicySupported=$false
                    UcpdProtectionStateKnown=$true; UcpdProtectionActive=$true
                }
                $protected = Get-PrivacyTargetApplicability `
                    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' `
                    -Name 'AllowNewsAndInterests' -Applicability $proProtected
                $protected.Applicable | Should -BeFalse
                $protected.Reason | Should -Match 'UCPD.*exact BAVR'

                $proUnprotected = $proProtected.PSObject.Copy()
                $proUnprotected.UcpdProtectionActive = $false
                (Get-PrivacyTargetApplicability `
                    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' `
                    -Name 'AllowNewsAndInterests' -Applicability $proUnprotected).Applicable | Should -BeTrue

                $proUnknown = $proProtected.PSObject.Copy()
                $proUnknown.UcpdProtectionStateKnown = $false
                (Get-PrivacyTargetApplicability `
                    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' `
                    -Name 'AllowNewsAndInterests' -Applicability $proUnknown).Applicable | Should -BeFalse
            }

            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $backup = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Backup-PrivacySettings.ps1') -Raw
            $prestate = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Assert-PrivacyPrestate.ps1') -Raw
            $apply = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Set-PrivacyRegistryTargets.ps1') -Raw
            $backup | Should -Match 'UcpdProtectionStateKnown'
            $backup | Should -Match 'UcpdProtectionActive'
            $prestate | Should -Match 'Privacy UCPD applicability changed before Apply'
            $apply | Should -Match 'UCPD now protects AllowNewsAndInterests'
            $apply.IndexOf('UCPD now protects AllowNewsAndInterests') | Should -BeLessThan $apply.IndexOf('$written = 0')
        }

        It 'Should load the UCPD dependency before Privacy applicability in complete verification' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $verifier = Get-Content (Join-Path $repo 'Tools/Verify-Complete-Hardening.ps1') -Raw
            $managementIndex = $verifier.IndexOf('$privacyManagementHelper =')
            $ucpdIndex = $verifier.IndexOf('$privacyUcpdHelper =')
            $applicabilityIndex = $verifier.IndexOf('$privacyApplicabilityHelper =')
            $tier1Index = $verifier.IndexOf('$privacyTier1Helper =')
            $userContextIndex = $verifier.IndexOf('$privacyUserContextHelper =')
            $windowsSearchIndex = $verifier.IndexOf('$privacyWindowsSearchHelper =')

            $managementIndex | Should -BeGreaterOrEqual 0
            $ucpdIndex | Should -BeGreaterThan $managementIndex
            $applicabilityIndex | Should -BeGreaterThan $ucpdIndex
            $tier1Index | Should -BeGreaterThan $applicabilityIndex
            $userContextIndex | Should -BeGreaterThan $tier1Index
            $windowsSearchIndex | Should -BeGreaterThan $userContextIndex
            $verifier | Should -Match 'foreach \(\$privacyHelper in @\([\s\S]*\$privacyManagementHelper,[\s\S]*\$privacyUcpdHelper,[\s\S]*\$privacyApplicabilityHelper,[\s\S]*\$privacyTier1Helper,[\s\S]*\$privacyUserContextHelper,[\s\S]*\$privacyWindowsSearchHelper'
        }

        It "Should verify original key existence as well as value existence" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $source = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Restore-PrivacyRegistryState.ps1') -Raw
            $source | Should -Match 'key-existence verification failed'
            $source | Should -Match 'Originally absent Privacy key contains unowned state'
            $source | Should -Match 'Validate all targets and schema fields before the first mutation'
            $source | Should -Match 'Mount-UserRegistryHiveForRestore -Sid \$sid'
            $source | Should -Match 'Dismount-UserRegistryHiveAfterRestore -Mount \$mount'
            $source | Should -Match 'Assert-PrivacyRegistrySnapshot -Snapshot \$snapshot -RestoreOnly'
            $source | Should -Match 'Get-PrivacyTier1Schema7RestorePolicyDefinition'
            $source | Should -Not -Match '\bGet-PrivacyTier1PolicyDefinition\b'
            $rollback = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $rollback | Should -Match 'Get-PrivacyTier1RestorePolicyDefinitions\.ps1'
            $rollback | Should -Match 'Get-PrivacyUserContext\.ps1'
            $rollback | Should -Match 'PrivacyWindowsSearch\.ps1'
            $rollback | Should -Match 'PrivacySearchPolicyNotification\.ps1'
            $rollback | Should -Match "Get-Command 'Invoke-PrivacyWindowsSearchUserState'"
            $rollback | Should -Match "Get-Command 'Send-PrivacySearchPolicyChangeNotification'"
            $rollback | Should -Match 'Restore-PrivacyRegistryState -BackupPath \$privacyPreStatePath'
        }

        It "Should not force-stop unowned dependent services" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $privacyServices = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Disable-TelemetryServices.ps1') -Raw
            $rollback = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $privacyServices | Should -Not -Match 'Stop-Service[^\r\n]+-Force'
            $rollback | Should -Not -Match 'Stop-Service[^\r\n]+-Force'
        }

        It 'Should execute only the sealed registry/service/task plan' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $invoke = Get-Content (Join-Path $repo 'Modules/Privacy/Public/Invoke-PrivacyHardening.ps1') -Raw
            $invoke | Should -Match 'Assert-PrivacyPrestate[\s\S]+Complete-ModuleBackup[\s\S]+Assert-PrivacyPrestate'
            $invoke | Should -Match 'Complete-ModuleBackup[\s\S]+Assert-PrivacyPrestate[\s\S]+-WindowsSearchPreflightAlreadyProven[\s\S]+Set-PrivacyRegistryTargets'
            $invoke | Should -Match 'Set-PrivacyRegistryTargets -Snapshot \$privacySnapshot'
            $invoke | Should -Match '\$privacySnapshot\.ApplicableServiceNames'
            $invoke | Should -Match '\$privacySnapshot\.ApplicableScheduledTaskPaths'
            $invoke | Should -Not -Match '\$results \+= Set-TelemetrySettings'
            $invoke | Should -Not -Match '\$results \+= Set-OneDriveSettings'
            $invoke | Should -Match "Properties\.Remove\('AllowCrossDeviceClipboard'\)"
            $invoke | Should -Not -Match 'AllowCrossDeviceClipboard\.Value\s*=\s*1'
            foreach ($legacySetter in @(
                    'Set-PrivacyRegistrySection.ps1', 'Set-TelemetrySettings.ps1',
                    'Set-PersonalizationSettings.ps1', 'Set-AppPrivacySettings.ps1',
                    'Set-OneDriveSettings.ps1'
                )) {
                (Join-Path $repo "Modules/Privacy/Private/$legacySetter") | Should -Not -Exist
            }
        }

        It 'Should perform one native WindowsSearch read for Query and retain before/after reads for Refresh' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $windowsSearch = Get-Content (Join-Path $repo 'Modules/Privacy/Private/PrivacyWindowsSearch.ps1') -Raw
            $prestate = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Assert-PrivacyPrestate.ps1') -Raw

            $windowsSearch | Should -Match '\$afterApi = if \(\$Operation -eq ''RefreshWebResults''\)[\s\S]+Get-PrivacyWindowsSearchApiState[\s\S]+else \{[\s\S]+\$beforeApi'
            $prestate | Should -Match 'SchemaVersion -eq 7 -and[\s\S]+-not \$WindowsSearchPreflightAlreadyProven[\s\S]+Invoke-PrivacyWindowsSearchUserState -User \$searchUser -Operation Query'
        }

        It 'Should fail when sealed service or task applicability changes before verification' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $compliance = Get-Content (Join-Path $repo 'Modules/Privacy/Test-PrivacyCompliance.ps1') -Raw
            $compliance | Should -Match 'Privacy verification config service/task scope differs from the sealed snapshot'
            $compliance | Should -Match 'sealed applicable service disappeared'
            $compliance | Should -Match 'service appeared after applicability was sealed'
            $compliance | Should -Match 'sealed applicable task disappeared'
            $compliance | Should -Match 'task appeared after applicability was sealed'
            $compliance | Should -Match '\$installedServices\s*=\s*if \(\$configuredServiceNames\.Count -gt 0\) \{ @\(Get-Service -ErrorAction Stop\)'
            $compliance | Should -Match '\$installedTasks\s*=\s*if \(\$configuredTaskPaths\.Count -gt 0\) \{ @\(Get-ScheduledTask -ErrorAction Stop\)'
        }

        It 'Should use one exact runtime plan for DryRun and backup service/task applicability' {
            InModuleScope Privacy {
                $config = [PSCustomObject]@{
                    Mode = 'Strict'
                    Services = @([PSCustomObject]@{ Name = 'DiagTrack' })
                    ScheduledTasks = @('\Microsoft\Windows\NoID\Task')
                }
                Mock Get-PrivacyTargetPlan {
                    [PSCustomObject]@{
                        DeclaredCount = 2
                        ApplicableTargets = @([PSCustomObject]@{ Path='HKLM:\SOFTWARE\Policies\Microsoft\NoID'; Name='A' })
                        NotApplicableTargets = @([PSCustomObject]@{ Path='HKLM:\SOFTWARE\Policies\Microsoft\NoID'; Name='B' })
                        NotCheckedTargets = @()
                    }
                }
                Mock Get-Service { @([PSCustomObject]@{ Name='DiagTrack'; Status='Stopped' }) }
                Mock Get-ScheduledTask { @([PSCustomObject]@{ TaskPath='\Microsoft\Windows\NoID\'; TaskName='Task'; State='Disabled' }) }

                $plan = Get-PrivacyRuntimeTargetPlan -Config $config
                $plan.DeclaredChecks | Should -Be 4
                $plan.ApplicableChecks | Should -Be 3
                $plan.NotApplicableChecks | Should -Be 1
                @($plan.ApplicableServiceNames).Count | Should -Be 1
                @($plan.ApplicableServiceNames) | Should -Contain 'DiagTrack'
                @($plan.ApplicableScheduledTaskPaths).Count | Should -Be 1
                @($plan.ApplicableScheduledTaskPaths) | Should -Contain '\Microsoft\Windows\NoID\Task'
            }

            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $backup = Get-Content (Join-Path $repo 'Modules/Privacy/Private/Backup-PrivacySettings.ps1') -Raw
            $invoke = Get-Content (Join-Path $repo 'Modules/Privacy/Public/Invoke-PrivacyHardening.ps1') -Raw
            $backup | Should -Match '\$runtimePlan\s*=\s*Get-PrivacyRuntimeTargetPlan -Config \$Config'
            $invoke | Should -Match '\$runtimePlan\s*=\s*Get-PrivacyRuntimeTargetPlan -Config \$config'
            $invoke | Should -Match 'ChangesMade\s*=\s*0'
        }
    }

    Context "Function Execution - DryRun Mode" {
        # These tests require admin rights and Core modules - skipped on CI

        It "Should execute without errors in DryRun mode" -Tag 'Interactive' {
            { Invoke-UnitNonInteractive { Invoke-PrivacyHardening -Mode 'MSRecommended' -DryRun } } | Should -Not -Throw
        }
    }

    Context "Return Object Structure" {
        # Skipped - requires proper environment
    }

    Context "Compliance Testing" {
        # Skipped - Test-PrivacyCompliance requires different parameters
    }
}

AfterAll {
    # Clean up
    Remove-Module Privacy -Force -ErrorAction SilentlyContinue
}
