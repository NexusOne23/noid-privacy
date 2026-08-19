#Requires -Version 5.1

<#
.SYNOPSIS
    Unit tests for EdgeHardening module

.DESCRIPTION
    Pester v5 tests for the EdgeHardening module functionality.
    Tests return values, DryRun behavior, and configuration handling.

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
    $script:RunningOnWindows = ($env:OS -eq 'Windows_NT')
    # Import the module being tested
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/EdgeHardening/EdgeHardening.psm1"

    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force
    }
    else {
        throw "Module not found: $modulePath"
    }

    # Import Core modules for testing
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
}

Describe "EdgeHardening Module" {

    Context "Module Structure" {

        It "Should export Invoke-EdgeHardening function" {
            $command = Get-Command -Name Invoke-EdgeHardening -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It "Should export Test-EdgeHardening function" {
            $command = Get-Command -Name Test-EdgeHardening -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It "Should have correct function type" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.CommandType | Should -Be 'Function'
        }

        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.CmdletBinding | Should -Be $true
        }
    }

    Context "Function Parameters" {

        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }

        It "DryRun parameter should be a switch" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.Parameters['DryRun'].ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It "Should have AllowExtensions parameter" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.Parameters.ContainsKey('AllowExtensions') | Should -Be $true
        }

        It "AllowExtensions parameter should be a switch" {
            $command = Get-Command -Name Invoke-EdgeHardening
            $command.Parameters['AllowExtensions'].ParameterType.Name | Should -Be 'SwitchParameter'
        }
    }

    Context 'Installation discovery' {
        It 'selects the newest parseable executable and reports an unreadable residual copy' {
            InModuleScope EdgeHardening {
                $oldProgramFiles = $env:ProgramFiles
                $oldProgramFilesX86 = ${env:ProgramFiles(x86)}
                try {
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
                                VersionInfo = [PSCustomObject]@{ FileVersion = '151.0.100.2 stable' }
                            }
                        }
                        return [PSCustomObject]@{
                            VersionInfo = [PSCustomObject]@{ FileVersion = 'not-a-version' }
                        }
                    }

                    $status = Get-EdgeInstallationStatus
                    $status.Installed | Should -BeTrue
                    $status.Path | Should -BeExactly $newestPath
                    $status.Version | Should -BeExactly '151.0.100.2'
                    $status.Major | Should -Be 151
                    @($status.Installations).Count | Should -Be 1
                    @($status.UnreadablePaths).Count | Should -Be 1
                    $status.UnreadablePaths[0] | Should -BeExactly $stalePath
                }
                finally {
                    $env:ProgramFiles = $oldProgramFiles
                    ${env:ProgramFiles(x86)} = $oldProgramFilesX86
                }
            }
        }

        It 'discovers an offline profile installation without a running Explorer process' {
            InModuleScope EdgeHardening {
                $oldProgramFiles = $env:ProgramFiles
                $oldProgramFilesX86 = ${env:ProgramFiles(x86)}
                try {
                    $env:ProgramFiles = ''
                    ${env:ProgramFiles(x86)} = ''
                    $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
                    $profilePath = Join-Path $TestDrive 'OfflineUser'
                    $edgePath = Join-Path $profilePath 'AppData\Local\Microsoft\Edge\Application\msedge.exe'
                    $edgeProfile = [PSCustomObject]@{
                        PSChildName = 'S-1-5-21-1-2-3-1009'
                        ProfileImagePath = $profilePath
                    }
                    $edgeProfile | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                        param($Name, $DefaultValue, $Options)
                        $null = $Options
                        if ($Name -ceq 'ProfileImagePath') { return $this.ProfileImagePath }
                        return $DefaultValue
                    }

                    Mock Test-Path {
                        param($LiteralPath)
                        return [string]$LiteralPath -in @($profileList, $edgePath)
                    }
                    Mock Get-ChildItem { @($edgeProfile) }
                    Mock Get-Process { throw 'Explorer must not be consulted for machine-policy discovery' }
                    Mock Get-Item {
                        [PSCustomObject]@{
                            VersionInfo = [PSCustomObject]@{ FileVersion = '150.0.1.0' }
                        }
                    }

                    $status = Get-EdgeInstallationStatus
                    $status.Installed | Should -BeTrue
                    $status.Path | Should -BeExactly $edgePath
                    $status.Version | Should -BeExactly '150.0.1.0'
                    @($status.Paths) | Should -Contain $edgePath
                    Should -Invoke Get-Process -Times 0 -Exactly
                }
                finally {
                    $env:ProgramFiles = $oldProgramFiles
                    ${env:ProgramFiles(x86)} = $oldProgramFilesX86
                }
            }
        }
    }

    Context "Configuration" {

        It "EdgePolicies.json should exist" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/EdgeHardening/Config/EdgePolicies.json"
            Test-Path $configPath | Should -Be $true
        }

        It "EdgePolicies.json should be valid JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/EdgeHardening/Config/EdgePolicies.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It "EdgePolicies.json should contain policies" {
            # EdgePolicies.json is a flat array of policy entries, not an object-with-.Policies wrapper.
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/EdgeHardening/Config/EdgePolicies.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config | Should -Not -BeNullOrEmpty
            @($config).Count | Should -BeGreaterThan 0
        }

        It "All policies should be valid objects" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/EdgeHardening/Config/EdgePolicies.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config | Should -Not -BeNullOrEmpty
            foreach ($entry in @($config)) {
                $entry.KeyName    | Should -Not -BeNullOrEmpty
                $entry.ValueName  | Should -Not -BeNullOrEmpty
                $entry.Type       | Should -Not -BeNullOrEmpty
            }
        }

        It "Should distinguish 26 managed values from one LGPO metadata row" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $config = Get-Content (Join-Path $repo 'Modules/EdgeHardening/Config/EdgePolicies.json') -Raw | ConvertFrom-Json
            $summary = Get-Content (Join-Path $repo 'Modules/EdgeHardening/Config/Summary.json') -Raw | ConvertFrom-Json
            @($config).Count | Should -Be 27
            @($config | Where-Object { $_.ValueName -notmatch '^\*\*delvals' }).Count | Should -Be 26
            @($config | Where-Object { $_.ValueName -match '^\*\*delvals' }).Count | Should -Be 1
            $summary.MicrosoftBaselinePolicyCount | Should -Be 19
            $summary.PrivacyAdditionPolicyCount | Should -Be 7
            $summary.ManagedPolicyCount | Should -Be 26
            $summary.DefaultSelectedPolicyCount | Should -Be 25
            $summary.StrictSelectedPolicyCount | Should -Be 26
            $summary.LegacyV225ManagedPolicyCount | Should -Be 23
            $summary.OfficialPackage.SizeBytes | Should -Be 400613
            $summary.OfficialPackage.Sha256 | Should -Be 'ac54ff9ccb9e86c4f65d8be7968e499f2ed1f9daa4aecb6294f429141c943e3f'
        }

        It "Should derive exact default and strict target inventories" {
            InModuleScope EdgeHardening {
                @(Get-EdgePolicyTargets -AllowExtensions).Count | Should -Be 25
                @(Get-EdgePolicyTargets).Count | Should -Be 26
                @(Get-EdgePolicyTargets | Where-Object Origin -eq 'MicrosoftBaseline').Count | Should -Be 19
                @(Get-EdgePolicyTargets | Where-Object Origin -eq 'NoIDPrivacy').Count | Should -Be 7
                @(Get-EdgePolicyTargets -AllowExtensions -LegacyV225).Count | Should -Be 22
                @(Get-EdgePolicyTargets -LegacyV225).Count | Should -Be 23
                @(Get-EdgePolicyTargets | Where-Object Name -match '^\*\*delvals').Count | Should -Be 0
            }
        }

        It 'Should gate four managed SmartScreen targets by authoritative domain/MDM applicability' {
            InModuleScope EdgeHardening {
                $unmanaged = [PSCustomObject]@{
                    SchemaVersion = 1; EditionFamily = 'Professional'; OperatingSystemSKU = 48
                    EditionID = 'Professional'; DomainJoined = $false; MdmRegistered = $false
                    MdmEditionEligible = $true; ManagedWindowsEligible = $false
                    EvidenceSource = 'UnmanagedWindows'
                }
                $managed = [PSCustomObject]@{
                    SchemaVersion = 1; EditionFamily = 'Professional'; OperatingSystemSKU = 48
                    EditionID = 'Professional'; DomainJoined = $false; MdmRegistered = $true
                    MdmEditionEligible = $true; ManagedWindowsEligible = $true
                    EvidenceSource = 'WindowsMdmRegistrationApi'
                }
                $unmanagedTargets = @(Get-EdgePolicyTargets -RuntimeApplicability $unmanaged)
                $managedTargets = @(Get-EdgePolicyTargets -RuntimeApplicability $managed)

                @($unmanagedTargets | Where-Object { -not $_.Applicable }).Count | Should -Be 4
                @($unmanagedTargets | Where-Object Applicable).Count | Should -Be 22
                @($managedTargets | Where-Object { -not $_.Applicable }).Count | Should -Be 0
                @($managedTargets | Where-Object Applicable).Count | Should -Be 26

                # WHICH four, not just how many: swapping the gated set in
                # Summary.json for any other four declared baseline names kept
                # every count identical (4 not-applicable, 22 applicable) while
                # the four SmartScreen policies silently stopped being gated and
                # four unrelated ones were withheld from unmanaged machines.
                @($unmanagedTargets | Where-Object { -not $_.Applicable } |
                    Select-Object -ExpandProperty Name | Sort-Object) |
                    Should -Be @(
                        'PreventSmartScreenPromptOverride',
                        'PreventSmartScreenPromptOverrideForFiles',
                        'SmartScreenEnabled',
                        'SmartScreenPuaEnabled'
                    )
                foreach ($ungatedName in @('SitePerProcess', 'AuthSchemes', 'SSLErrorOverrideAllowed', 'DynamicCodeSettings')) {
                    @($unmanagedTargets | Where-Object { $_.Name -ceq $ungatedName -and $_.Applicable }).Count |
                        Should -Be 1 -Because "$ungatedName must stay applicable on unmanaged Windows"
                }
            }
        }

        It 'pins the exact value every managed Edge policy writes' {
            # Test-EdgePolicies verifies live registry state against the same
            # EdgePolicies.json the module applies, so a config-side inversion -
            # DiagnosticData 0 -> 2 (full telemetry), TrackingPrevention 2 -> 0
            # (off) - was applied, verified as compliant, and reported green end
            # to end. These literals are the only authority outside that file.
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $config = Get-Content (Join-Path $repo 'Modules/EdgeHardening/Config/EdgePolicies.json') -Raw | ConvertFrom-Json

            $expectedPolicies = [ordered]@{
                'SitePerProcess'                                          = @('REG_DWORD', 1)
                'AuthSchemes'                                             = @('REG_SZ', 'ntlm,negotiate')
                'NativeMessagingUserLevelHosts'                           = @('REG_DWORD', 0)
                'SmartScreenEnabled'                                      = @('REG_DWORD', 1)
                'PreventSmartScreenPromptOverride'                        = @('REG_DWORD', 1)
                'PreventSmartScreenPromptOverrideForFiles'                = @('REG_DWORD', 1)
                'SSLErrorOverrideAllowed'                                 = @('REG_DWORD', 0)
                'SmartScreenPuaEnabled'                                   = @('REG_DWORD', 1)
                'BasicAuthOverHttpEnabled'                                = @('REG_DWORD', 0)
                'InternetExplorerIntegrationReloadInIEModeAllowed'        = @('REG_DWORD', 0)
                'SharedArrayBufferUnrestrictedAccessAllowed'              = @('REG_DWORD', 0)
                'BrowserLegacyExtensionPointsBlockingEnabled'             = @('REG_DWORD', 1)
                'InternetExplorerModeToolbarButtonEnabled'                = @('REG_DWORD', 0)
                'TyposquattingCheckerEnabled'                             = @('REG_DWORD', 1)
                'InternetExplorerIntegrationZoneIdentifierMhtFileAllowed' = @('REG_DWORD', 0)
                'DynamicCodeSettings'                                     = @('REG_DWORD', 1)
                'ApplicationBoundEncryptionEnabled'                       = @('REG_DWORD', 1)
                'EnableUnsafeSwiftShader'                                 = @('REG_DWORD', 0)
                'PersonalizationReportingEnabled'                         = @('REG_DWORD', 0)
                'DiagnosticData'                                          = @('REG_DWORD', 0)
                'TrackingPrevention'                                      = @('REG_DWORD', 2)
                'EdgeShoppingAssistantEnabled'                            = @('REG_DWORD', 0)
                'SearchSuggestEnabled'                                    = @('REG_DWORD', 0)
                'AddressBarTrendingSuggestEnabled'                        = @('REG_DWORD', 0)
                'EdgeReadingModeServiceBasedExtractionEnabled'            = @('REG_DWORD', 0)
            }

            foreach ($name in $expectedPolicies.Keys) {
                $row = @($config | Where-Object {
                        $_.ValueName -ceq $name -and
                        $_.KeyName -ceq '[Software\Policies\Microsoft\Edge'
                    })
                $row.Count | Should -Be 1 -Because "exactly one managed row must declare $name"
                [string]$row[0].Type | Should -BeExactly $expectedPolicies[$name][0] -Because "the registry kind of $name"
                $row[0].Data | Should -BeExactly $expectedPolicies[$name][1] -Because "the enforced value of $name"
            }

            # The extension blocklist subkey: the LGPO delete-values metadata row
            # plus the block-all entry.
            $blocklist = @($config | Where-Object {
                    $_.KeyName -ceq '[Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
                })
            $blocklist.Count | Should -Be 2
            @($blocklist | Where-Object { $_.ValueName -ceq '**delvals.' }).Count | Should -Be 1
            $blockAll = @($blocklist | Where-Object { $_.ValueName -ceq '1' })
            $blockAll.Count | Should -Be 1
            [string]$blockAll[0].Data | Should -BeExactly '*'

            # Closed inventory: 25 managed values + 2 blocklist rows, nothing else.
            @($config).Count | Should -Be 27
        }

        It 'Should stage policies above an installed Edge version while preserving their minimum-version metadata' {
            InModuleScope EdgeHardening {
                $edge150 = [PSCustomObject]@{
                    Installed = $true; Path = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
                    Version = '150.0.0.0'; Major = 150
                }
                $targets = @(Get-EdgePolicyTargets -EdgeInstallationStatus $edge150)
                @($targets | Where-Object { -not $_.Applicable }).Count | Should -Be 0
                $readingMode = $targets | Where-Object Name -eq 'EdgeReadingModeServiceBasedExtractionEnabled'
                $readingMode.Applicable | Should -BeTrue
                $readingMode.MinimumEdgeMajor | Should -Be 151
                ($targets | Where-Object Name -eq 'SearchSuggestEnabled').Applicable | Should -BeTrue
            }
        }

        It 'Should distinguish domain, eligible MDM and ineligible-edition MDM matrices' {
            InModuleScope EdgeHardening {
                function Get-FakeEditionKey {
                    param([string]$EditionID)
                    $key = [PSCustomObject]@{ StoredEditionID = $EditionID }
                    $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                        param($name, $fallback)
                        if ($name -eq 'EditionID') { return $this.StoredEditionID }
                        return $fallback
                    }
                    return $key
                }

                $script:domainJoined = $false
                $script:sku = 48
                $script:editionId = 'Professional'
                $script:mdmRegistered = $false
                Mock Get-CimInstance {
                    param($ClassName)
                    if ($ClassName -eq 'Win32_OperatingSystem') {
                        return [PSCustomObject]@{ OperatingSystemSKU = $script:sku }
                    }
                    if ($ClassName -eq 'Win32_ComputerSystem') {
                        return [PSCustomObject]@{ PartOfDomain = $script:domainJoined }
                    }
                    throw "Unexpected CIM class $ClassName"
                }
                Mock Get-Item { Get-FakeEditionKey -EditionID $script:editionId }
                Mock Test-EdgeMdmRegistration { $script:mdmRegistered }

                $script:domainJoined = $true
                (Get-EdgeRuntimeApplicability).ManagedWindowsEligible | Should -BeTrue

                $script:domainJoined = $false
                $script:mdmRegistered = $true
                (Get-EdgeRuntimeApplicability).EvidenceSource | Should -Be 'WindowsMdmRegistrationApi'

                $script:sku = 101
                $script:editionId = 'Core'
                $homeMdm = Get-EdgeRuntimeApplicability
                $homeMdm.ManagedWindowsEligible | Should -BeFalse
                $homeMdm.EvidenceSource | Should -Be 'MdmRegisteredButEditionIneligible'
            }
        }
    }

    Context "DryRun Behavior" {
        # These tests require Core modules and admin rights - skipped on CI

        It "Should accept DryRun parameter without errors" -Tag 'Interactive' -Skip:($PSVersionTable.PSEdition -ne 'Desktop' -and -not [bool]$IsWindows) {
            { Invoke-UnitNonInteractive { Invoke-EdgeHardening -DryRun -ErrorAction Stop } } | Should -Not -Throw
        }

        It 'Should count DryRun targets as previewed and never as applied or runtime-verified' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $edgeRoot = Join-Path $repo 'Modules/EdgeHardening'
            $setSource = Get-Content (Join-Path $edgeRoot 'Private/Set-EdgePolicies.ps1') -Raw
            $invokeSource = Get-Content (Join-Path $edgeRoot 'Public/Invoke-EdgeHardening.ps1') -Raw
            $setSource | Should -Match 'if \(\$DryRun\)[\s\S]*?\$result\.Previewed\+\+'
            $setSource | Should -Not -Match 'if \(\$DryRun\)[\s\S]{0,240}?\$result\.Applied\+\+'
            $setSource | Should -Match '\$completedCount = if \(\$DryRun\) \{ \$result\.Previewed \} else \{ \$result\.Applied \}'
            $invokeSource | Should -Match 'PoliciesPreviewed\s*=\s*0'
            $invokeSource | Should -Match '\$result\.PoliciesPreviewed \+ \$result\.PoliciesNotApplicable'
            $invokeSource | Should -Match 'RuntimePolicyVerified\s*=\s*\$null'
        }

        It 'Should stage the complete documented policy set when installed Edge is older than v139 without claiming runtime consumption' {
            InModuleScope EdgeHardening {
                Mock Write-Log { }
                Mock Get-EdgeRuntimeApplicability {
                    [PSCustomObject]@{
                        SchemaVersion=1; EditionFamily='Enterprise'; OperatingSystemSKU=4
                        EditionID='Enterprise'; DomainJoined=$false; MdmRegistered=$false
                        MdmEditionEligible=$true; ManagedWindowsEligible=$false
                        EvidenceSource='UnmanagedWindows'
                    }
                }
                Mock Get-EdgePolicyTargets {
                    @([PSCustomObject]@{
                            Path='HKLM:\Software\Policies\Microsoft\Edge'; Name='Policy'
                            Type='DWord'; Value=1; Origin='MicrosoftBaseline'
                            Applicable=$true; NotApplicableReason=$null
                        })
                }
                Mock Get-EdgeInstallationStatus {
                    [PSCustomObject]@{
                        Installed=$true; Path='C:\msedge.exe'; Version='122.0.2365.106'; Major=122
                        Paths=@('C:\msedge.exe')
                        Installations=@([PSCustomObject]@{ Path='C:\msedge.exe'; Version='122.0.2365.106' })
                        UnreadablePaths=@()
                    }
                }
                Mock Set-EdgePolicies {
                    [PSCustomObject]@{
                        Success=$true; Selected=1; Applied=0; Previewed=1
                        Skipped=0; NotApplicable=0; Errors=@()
                    }
                }

                $result = Invoke-EdgeHardening -DryRun -AllowExtensions

                $result.Success | Should -BeTrue
                $result.Status | Should -Be 'DryRun'
                $result.EdgeVersion | Should -Be '122.0.2365.106'
                $result.PoliciesSelected | Should -Be 1
                $result.PoliciesApplied | Should -Be 0
                $result.PoliciesPreviewed | Should -Be 1
                $result.BackupCreated | Should -BeFalse
                $result.ComplianceVerified | Should -BeNullOrEmpty
                @($result.Errors).Count | Should -Be 0
                @($result.Warnings).Count | Should -Be 1
                $result.Warnings[0] | Should -Match 'policies were staged, but current runtime consumption is not asserted'
                $result.RuntimeApplicability | Should -BeLike 'EdgeOlderThan139Detected;PoliciesStagedForUpdate;*'
                Should -Invoke Set-EdgePolicies -Times 1 -Exactly
            }
        }
    }

    Context "Test-EdgeHardening Function" {

        It "Should run Test-EdgeHardening without errors" -Skip:($PSVersionTable.PSEdition -ne 'Desktop' -and -not [bool]$IsWindows) {
            { Test-EdgeHardening -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should return compliance results" -Skip:($PSVersionTable.PSEdition -ne 'Desktop' -and -not [bool]$IsWindows) {
            $result = Test-EdgeHardening -ErrorAction SilentlyContinue
            $result | Should -Not -BeNullOrEmpty
        }

        It 'preserves the root policy-read failure and one stable result shape' {
            InModuleScope EdgeHardening {
                Mock Test-EdgePolicies {
                    [PSCustomObject]@{
                        Compliant = $false
                        Message = 'registry provider unavailable'
                        SelectedCount = 0
                        ApplicableCount = 0
                        NotApplicableCount = 0
                        CompliantCount = 0
                        NonCompliantCount = 1
                        Details = @()
                    }
                }

                $result = Test-EdgeHardening

                $result.Message | Should -BeLike '*registry provider unavailable*'
                $result.IntentKnown | Should -BeFalse
                $result.SelectedCount | Should -Be 0
                $result.ApplicableCount | Should -Be 0
                $result.NotApplicableCount | Should -Be 0
                $result.CompliantCount | Should -Be 0
                $result.NonCompliantCount | Should -Be 0
                $result.SkippedCount | Should -Be 0
                $result.ExtensionBlocklistActive | Should -BeNullOrEmpty
                @($result.Details).Count | Should -Be 0
                Should -Invoke Test-EdgePolicies -Times 1 -Exactly
            }
        }

        It 'marks the intent-free extension read as an observation instead of a failed choice' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $edgeRoot = Join-Path $repo 'Modules/EdgeHardening'
            $privateSource = Get-Content (
                Join-Path $edgeRoot 'Private/Test-EdgePolicies.ps1') -Raw
            $publicSource = Get-Content (
                Join-Path $edgeRoot 'Public/Test-EdgeHardening.ps1') -Raw

            $publicSource | Should -Match 'Test-EdgePolicies -AllowExtensions:\$false -ObserveExtensionWithoutIntent'
            $privateSource | Should -Match '\$optionalObservation = \$ObserveExtensionWithoutIntent'
            $privateSource | Should -Match 'if \(-not \$compliant -and -not \$optionalObservation\)'
            $privateSource | Should -Match 'Observed Edge extension block-all live state without a profile intent'
        }
    }

    Context "Exact registry BAVR" {
        It 'Should return exact success counters only after sealed backup, Apply and Verify succeed' {
            $snapshotPath = Join-Path $TestDrive 'edge-snapshot.json'
            '{}' | Set-Content -LiteralPath $snapshotPath -Encoding UTF8
            InModuleScope EdgeHardening -Parameters @{ SnapshotPath = $snapshotPath } {
                Mock Write-Log { }
                Mock Get-EdgeRuntimeApplicability {
                    [PSCustomObject]@{
                        SchemaVersion=1; EditionFamily='Professional'; OperatingSystemSKU=48
                        EditionID='Professional'; DomainJoined=$false; MdmRegistered=$false
                        MdmEditionEligible=$true; ManagedWindowsEligible=$false
                        EvidenceSource='UnmanagedWindows'
                    }
                }
                Mock Get-EdgePolicyTargets {
                    @([PSCustomObject]@{
                            Path='HKLM:\Software\Policies\Microsoft\Edge'; Name='Policy'
                            Type='DWord'; Value=1; Origin='MicrosoftBaseline'
                            Applicable=$true; NotApplicableReason=$null
                        })
                }
                Mock Get-EdgeInstallationStatus {
                    [PSCustomObject]@{ Installed=$false; Path=$null; Version=$null; Major=$null }
                }
                Mock Initialize-BackupSystem { $true }
                Mock Start-ModuleBackup { 'session-path' }
                Mock Backup-EdgePolicies {
                    [PSCustomObject]@{
                        Success=$true; Errors=@(); DeclaredTargets=1
                        TargetsBackedUp=1; NotApplicable=0; BackupPath=$SnapshotPath
                    }
                }
                Mock Assert-EdgePrestate { $true }
                Mock Complete-ModuleBackup { $true }
                Mock Set-EdgePolicies {
                    [PSCustomObject]@{ Success=$true; Selected=1; Applied=1; Skipped=0; NotApplicable=0; Errors=@() }
                }
                Mock Test-EdgePolicies {
                    [PSCustomObject]@{
                        Compliant=$true; CompliancePercentage=100; SelectedCount=1
                        ApplicableCount=1; NotApplicableCount=0; CompliantCount=1
                        NonCompliantCount=0; Message='exact'
                    }
                }
                $global:CurrentModule = ''
                $global:BackupIndex = @([PSCustomObject]@{
                        Module='EdgeHardening'; Type='EdgeHardening';
                        Name='EdgePolicies'; BackupFile=$SnapshotPath
                    })

                $result = Invoke-EdgeHardening -AllowExtensions
                $result.Success | Should -BeTrue
                $result.Status | Should -Be 'Applied'
                $result.BackupCreated | Should -BeTrue
                $result.PoliciesSelected | Should -Be 1
                $result.PoliciesApplied | Should -Be 1
                $result.PoliciesNotApplicable | Should -Be 0
                $result.ComplianceVerified | Should -BeTrue
                Should -Invoke Assert-EdgePrestate -Times 2 -Exactly
                Should -Invoke Set-EdgePolicies -Times 1 -Exactly
                Should -Invoke Test-EdgePolicies -Times 1 -Exactly
            }
        }

        It 'Should never enter Apply after failed or partial backup' {
            InModuleScope EdgeHardening {
                Mock Write-Log { }
                Mock Get-EdgeRuntimeApplicability {
                    [PSCustomObject]@{
                        SchemaVersion=1; EditionFamily='Professional'; OperatingSystemSKU=48
                        EditionID='Professional'; DomainJoined=$false; MdmRegistered=$false
                        MdmEditionEligible=$true; ManagedWindowsEligible=$false
                        EvidenceSource='UnmanagedWindows'
                    }
                }
                Mock Get-EdgePolicyTargets {
                    @([PSCustomObject]@{
                            Path='HKLM:\Software\Policies\Microsoft\Edge'; Name='Policy'
                            Type='DWord'; Value=1; Origin='MicrosoftBaseline'
                            Applicable=$true; NotApplicableReason=$null
                        })
                }
                Mock Get-EdgeInstallationStatus {
                    [PSCustomObject]@{ Installed=$false; Path=$null; Version=$null; Major=$null }
                }
                Mock Initialize-BackupSystem { $true }
                Mock Start-ModuleBackup { 'session-path' }
                Mock Backup-EdgePolicies {
                    [PSCustomObject]@{
                        Success=$true; Errors=@(); DeclaredTargets=1
                        TargetsBackedUp=0; NotApplicable=0; BackupPath=$null
                    }
                }
                Mock Set-EdgePolicies { throw 'Apply must not run' }
                Mock Complete-ModuleBackup { throw 'partial backup must not seal' }
                $global:CurrentModule = ''

                $result = Invoke-EdgeHardening -AllowExtensions
                $result.Success | Should -BeFalse
                $result.Status | Should -Be 'Failed'
                $result.BackupCreated | Should -BeFalse
                $result.PoliciesApplied | Should -Be 0
                Should -Invoke Set-EdgePolicies -Times 0 -Exactly
                Should -Invoke Complete-ModuleBackup -Times 0 -Exactly
            }
        }

        It "Should seal a target-counted schema and restore key existence exactly" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $backupSource = Get-Content (Join-Path $repo 'Modules/EdgeHardening/Private/Backup-EdgePolicies.ps1') -Raw
            $restoreSource = Get-Content (Join-Path $repo 'Modules/EdgeHardening/Private/Restore-EdgePolicies.ps1') -Raw
            $backupSource | Should -Match 'SchemaVersion\s*=\s*6'
            $backupSource | Should -Match 'RuntimeApplicability\s*=\s*\$RuntimeApplicability'
            $backupSource | Should -Match 'EdgeInstallationStatus\s*=\s*\$EdgeInstallationStatus'
            $backupSource | Should -Match 'ApplyType\s*=\s*\[string\]\$target.Type'
            $backupSource | Should -Match 'TargetCount\s*=\s*\$entries.Count'
            $backupSource | Should -Match 'Assert-EdgePolicySnapshot'
            $restoreSource | Should -Match 'Assert-EdgePolicySnapshot'
            $restoreSource | Should -Match 'Edge key-existence verification failed'
            $restoreSource | Should -Match 'Originally absent Edge key contains unowned state'
        }

        It "Should reject a string masquerading as the Boolean profile flag" {
            InModuleScope EdgeHardening {
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 4; CapturedAt = (Get-Date).ToUniversalTime().ToString('o')
                    AllowExtensions = 'false'; TargetCount = 1; Entries = @()
                }
                { Assert-EdgePolicySnapshot -Snapshot $snapshot } | Should -Throw '*Boolean profile*'
            }
        }

        It 'Should keep legacy schema-4 snapshots bound to the closed 23-value v2.2.5 inventory' {
            InModuleScope EdgeHardening {
                $entries = @(Get-EdgePolicyTargets -LegacyV225 | ForEach-Object {
                        [PSCustomObject]@{
                            Path = $_.Path; Name = $_.Name; KeyExisted = $false
                            Exists = $false; Type = $null; Value = $null
                        }
                    })
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 4
                    CapturedAt = (Get-Date).ToUniversalTime().ToString('o')
                    AllowExtensions = $false
                    TargetCount = $entries.Count
                    Entries = $entries
                }
                $entries.Count | Should -Be 23
                { Assert-EdgePolicySnapshot -Snapshot $snapshot } | Should -Not -Throw
                try {
                    Set-StrictMode -Version Latest
                    { Assert-EdgePolicySnapshot -Snapshot $snapshot -RestoreOnly } | Should -Not -Throw
                }
                finally {
                    Set-StrictMode -Off
                }
                $snapshot.Entries = @($snapshot.Entries | Select-Object -First 22)
                $snapshot.TargetCount = 22
                { Assert-EdgePolicySnapshot -Snapshot $snapshot -RestoreOnly } |
                    Should -Throw '*complete frozen profile inventory*'
            }
        }

        It 'Should load sealed Edge restores without the current Apply target helper' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $rollbackSource = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $restoreSource = Get-Content (Join-Path $repo 'Modules/EdgeHardening/Private/Restore-EdgePolicies.ps1') -Raw

            $rollbackSource | Should -Not -Match 'Get-EdgePolicyTargets\.ps1'
            $rollbackSource | Should -Match 'Assert-EdgePolicySnapshot -Snapshot \$json -RestoreOnly'
            $restoreSource | Should -Match 'Assert-EdgePolicySnapshot -Snapshot \$snapshot -RestoreOnly'
        }

        It 'Should require each frozen Edge restore schema to be complete' {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $validator = Get-Content (Join-Path $repo 'Modules/EdgeHardening/Private/Assert-EdgePolicySnapshot.ps1') -Raw

            $validator | Should -Match 'expectedDeclaredCount = switch \(\$schemaVersion\)'
            $validator | Should -Match '4 \{ if \(\[bool\]\$Snapshot.AllowExtensions\) \{ 22 \} else \{ 23 \} \}'
            $validator | Should -Match '6 \{ if \(\[bool\]\$Snapshot.AllowExtensions\) \{ 25 \} else \{ 26 \} \}'
            $validator | Should -Match 'complete frozen profile inventory'
        }

        It 'Should reject a frozen restore target listed as both applicable and NotApplicable' {
            InModuleScope EdgeHardening {
                $legacyTargets = @(Get-EdgePolicyTargets -AllowExtensions:$false -LegacyV225)
                $entries = @($legacyTargets | Select-Object -First 22 | ForEach-Object {
                        [PSCustomObject]@{
                            Path = $_.Path; Name = $_.Name; KeyExisted = $false
                            Exists = $false; Type = $null; Value = $null
                            ApplyType = [string]$_.Type; ApplyValue = $_.Value
                        }
                    })
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 5
                    CapturedAt = (Get-Date).ToUniversalTime().ToString('o')
                    AllowExtensions = $false
                    TargetCount = 22
                    DeclaredTargetCount = 23
                    NotApplicableCount = 1
                    RuntimeApplicability = [PSCustomObject]@{}
                    Entries = $entries
                    NotApplicable = @([PSCustomObject]@{
                            Path = [string]$entries[0].Path
                            Name = [string]$entries[0].Name
                            Reason = 'Synthetic overlap must be rejected'
                        })
                }

                { Assert-EdgePolicySnapshot -Snapshot $snapshot -RestoreOnly } |
                    Should -Throw '*both applicable and NotApplicable*'
            }
        }

        It 'Should reject an extension block target in the frozen allow-extensions profile' {
            InModuleScope EdgeHardening {
                $targets = @(Get-EdgePolicyTargets -AllowExtensions)
                $entries = @($targets | ForEach-Object {
                        [PSCustomObject]@{
                            Path = $_.Path; Name = $_.Name; KeyExisted = $false
                            Exists = $false; Type = $null; Value = $null
                            ApplyType = [string]$_.Type; ApplyValue = $_.Value
                        }
                    })
                $entries[0].Path = 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
                $entries[0].Name = '1'
                $snapshot = [PSCustomObject]@{
                    SchemaVersion = 6
                    CapturedAt = (Get-Date).ToUniversalTime().ToString('o')
                    AllowExtensions = $true
                    TargetCount = 25
                    DeclaredTargetCount = 25
                    NotApplicableCount = 0
                    RuntimeApplicability = [PSCustomObject]@{}
                    EdgeInstallationStatus = [PSCustomObject]@{}
                    Entries = $entries
                    NotApplicable = @()
                }

                { Assert-EdgePolicySnapshot -Snapshot $snapshot -RestoreOnly } |
                    Should -Throw '*invalid, duplicate or unowned target*'
            }
        }

        It "Should fail closed and retain an incomplete unsealed backup" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $invokeSource = Get-Content (Join-Path $repo 'Modules/EdgeHardening/Public/Invoke-EdgeHardening.ps1') -Raw
            $invokeSource | Should -Match 'TargetsBackedUp\s*-ne\s*\$applicableTargets.Count'
            $invokeSource | Should -Match 'registered.Count\s*-ne\s*1'
            $invokeSource | Should -Match 'Assert-EdgePrestate -Snapshot \$sealedSnapshot'
            $invokeSource | Should -Match 'Save-IncompleteModuleBackup'
        }

        It "Should enforce overlap restore ordering through the sealed manifest" {
            # The old form of this test grepped Rollback.ps1 for the phrase
            # 'AntiAI...EdgeHardening...same Edge policy' - which the guard's own
            # COMMENT satisfies whether or not any code enforces it. The decision
            # is now a pure function; assert it by value, in both sealed orders.
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            . (Join-Path $repo 'Core/Rollback.ps1')

            # Requesting only the EARLIER module strands the later one on the key.
            {
                Assert-NoIDEdgePolicyOverlapRestore `
                    -SessionModuleNames @('AntiAI', 'EdgeHardening') `
                    -RequestedModules @('AntiAI')
            } | Should -Throw '*AntiAI overlaps the later EdgeHardening module*'
            {
                Assert-NoIDEdgePolicyOverlapRestore `
                    -SessionModuleNames @('EdgeHardening', 'AntiAI') `
                    -RequestedModules @('EdgeHardening')
            } | Should -Throw '*EdgeHardening overlaps the later AntiAI module*'

            # Which module is "earlier" comes from sealed manifest order, not from
            # an assumed framework priority.
            {
                Assert-NoIDEdgePolicyOverlapRestore `
                    -SessionModuleNames @('EdgeHardening', 'AntiAI') `
                    -RequestedModules @('AntiAI')
            } | Should -Not -Throw

            # Restoring both, the whole session, only the later module, or a
            # session without the pair are all allowed.
            {
                Assert-NoIDEdgePolicyOverlapRestore `
                    -SessionModuleNames @('AntiAI', 'EdgeHardening') `
                    -RequestedModules @('AntiAI', 'EdgeHardening')
            } | Should -Not -Throw
            {
                Assert-NoIDEdgePolicyOverlapRestore `
                    -SessionModuleNames @('AntiAI', 'EdgeHardening') `
                    -RequestedModules @()
            } | Should -Not -Throw
            {
                Assert-NoIDEdgePolicyOverlapRestore `
                    -SessionModuleNames @('AntiAI', 'EdgeHardening') `
                    -RequestedModules @('EdgeHardening')
            } | Should -Not -Throw
            {
                Assert-NoIDEdgePolicyOverlapRestore `
                    -SessionModuleNames @('Privacy', 'EdgeHardening') `
                    -RequestedModules @('EdgeHardening')
            } | Should -Not -Throw

            # Restore still walks the sealed module list in reverse.
            $rollbackSource = Get-Content (Join-Path $repo 'Core/Rollback.ps1') -Raw
            $rollbackSource | Should -Match '\[array\]::Reverse\(\$reversedModules\)'
        }
    }
}

AfterAll {
    # Cleanup
    Remove-Module EdgeHardening -ErrorAction SilentlyContinue
}
