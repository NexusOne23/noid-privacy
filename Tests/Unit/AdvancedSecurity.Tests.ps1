#Requires -Version 5.1

<#
.SYNOPSIS
    Unit tests for AdvancedSecurity module

.DESCRIPTION
    Pester v5 tests for the AdvancedSecurity module functionality.
    Tests return values, DryRun behavior, profile handling, and configuration.

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
    # Production load order: Core dependencies FIRST (Logger.ps1 declares Write-Log;
    # other Core/* files reference it). Importantly, these are dot-sourced into the
    # GLOBAL scope via `${function:global:...}` indirection so the module-under-test
    # can resolve Write-Log when Import-Module isolates its session state.
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:RunningOnWindows = $PSVersionTable.PSEdition -eq 'Desktop' -or [bool]$IsWindows
    $coreModules = @("Logger.ps1", "Config.ps1", "Validator.ps1", "Rollback.ps1", "NonInteractive.ps1")
    $corePath = Join-Path $repoRoot "Core"

    foreach ($module in $coreModules) {
        $moduleFile = Join-Path $corePath $module
        if (Test-Path $moduleFile) {
            . $moduleFile
        }
    }

    # Promote Write-Log + co. into the global function table so the imported
    # module's session state can resolve them. Production does the equivalent
    # via dot-source-everywhere (NoIDPrivacy.ps1 -> Framework.ps1 -> Modules/*).
    foreach ($fn in 'Write-Log','Write-ErrorLog','Initialize-Logger','Get-LogFilePath','Get-ErrorContext','Test-NonInteractiveMode','Get-NonInteractiveValue','Write-NonInteractiveDecision') {
        if (Test-Path "function:$fn") {
            Set-Item -Path "function:global:$fn" -Value (Get-Item "function:$fn").ScriptBlock
        }
    }

    # Now Import-Module so Get-Command -Module + Pester surface introspection works.
    $modulePath = Join-Path $repoRoot "Modules" | Join-Path -ChildPath "AdvancedSecurity" | Join-Path -ChildPath "AdvancedSecurity.psm1"

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

    # Unit DryRun smoke tests must never block an unattended suite on product
    # prompts. Preserve the caller's process state exactly for AfterAll.
    $script:PreviousNonInteractiveEnvironment = [Environment]::GetEnvironmentVariable('NOIDPRIVACY_NONINTERACTIVE', 'Process')
    $env:NOIDPRIVACY_NONINTERACTIVE = 'true'
}

Describe "AdvancedSecurity Module" {

    Context "Module Structure" {

        It "Should export Invoke-AdvancedSecurity function" {
            $command = Get-Command -Name Invoke-AdvancedSecurity -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It "Should export Test-AdvancedSecurity function" {
            $command = Get-Command -Name Test-AdvancedSecurity -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }

        It "Should have correct function type" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.CommandType | Should -Be 'Function'
        }

        It "Should have CmdletBinding attribute" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.CmdletBinding | Should -Be $true
        }
    }

    Context "Function Parameters" {

        It "Should have SecurityProfile parameter" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('SecurityProfile') | Should -Be $true
        }

        It "Should have DryRun parameter" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('DryRun') | Should -Be $true
        }

        It "DryRun parameter should be a switch" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters['DryRun'].ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It "Should have DisableRDP parameter" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('DisableRDP') | Should -Be $true
        }

        It "Should have Force parameter" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('Force') | Should -Be $true
        }

        It "Should not expose a SkipBackup parameter" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('SkipBackup') | Should -Be $false
        }

        It "Should expose the explicit firewall-layer decision" {
            $command = Get-Command -Name Invoke-AdvancedSecurity
            $command.Parameters.ContainsKey('SkipFirewallLayer') | Should -Be $true
        }

        It "Should implement detection-prefill, explicit authority and repeated runtime warning" {
            $invokeSource = Get-Content (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/AdvancedSecurity/Public/Invoke-AdvancedSecurity.ps1') -Raw
            $detectionSource = Get-Content (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/AdvancedSecurity/Private/Get-FirewallControllerStatus.ps1') -Raw
            $invokeSource | Should -Match '\$firewallDefault = if \(\$firewallControllerStatus\.Detected\)'
            $invokeSource | Should -Match '\$SkipFirewallLayer = \(\$firewallChoice -eq ''Y''\)'
            $invokeSource | Should -Match 'Detection only chooses the suggested default; it never decides for you'
            $invokeSource | Should -Match 'Existing firewall rules not owned by NoID Privacy are preserved'
            $invokeSource | Should -Match 'Skip only if another product is actually controlling Windows Firewall rules'
            @([regex]::Matches($invokeSource, 'Write-FirewallControllerRuntimeWarning')).Count | Should -BeGreaterOrEqual 2
            foreach ($product in @('Windows Firewall Control', 'Bitdefender', 'ESET', 'Kaspersky')) {
                $detectionSource | Should -Match ([regex]::Escape($product))
            }
            $detectionSource | Should -Match 'Detection is advisory only'
        }
    }

    Context "Configuration" {

        It "SRP-Rules.json should exist" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AdvancedSecurity/Config/SRP-Rules.json"
            Test-Path $configPath | Should -Be $true
        }

        It "SRP-Rules.json should be valid JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AdvancedSecurity/Config/SRP-Rules.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It "WindowsUpdate.json should exist" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AdvancedSecurity/Config/WindowsUpdate.json"
            Test-Path $configPath | Should -Be $true
        }

        It "WindowsUpdate.json should be valid JSON" {
            $configPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Modules/AdvancedSecurity/Config/WindowsUpdate.json"
            { Get-Content $configPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }
    }

    Context "BAVR and decision integrity" {
        BeforeAll {
            $script:AdvancedRoot = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Modules/AdvancedSecurity'
        }

        It "Should apply the UPnP choice consistently to firewall and services" {
            $source = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $source | Should -Match 'Disable-RiskyPorts[\s\S]{0,120}-SkipUPnP:\(-not \$DisableUPnP\)'
            $source | Should -Match 'Stop-RiskyServices[\s\S]{0,120}-SkipUPnP:\(-not \$DisableUPnP\)'
        }

        It "Should never report partial risky-port or service work as success" {
            foreach ($name in @('Disable-RiskyPorts.ps1', 'Stop-RiskyServices.ps1')) {
                $source = Get-Content (Join-Path $script:AdvancedRoot "Private/$name") -Raw
                $source | Should -Not -Match 'Partial success'
                $source | Should -Not -Match 'Completed with.*errors[\s\S]{0,160}return \$true'
            }
        }

        It "Should not remove live administrative shares inside exact BAVR" {
            $source = Get-Content (Join-Path $script:AdvancedRoot 'Private/Disable-AdminShares.ps1') -Raw
            $source | Should -Not -Match '\bRemove-SmbShare\b'
        }

        It "Should own and restore the TLS version parent keys created by Apply" {
            $targets = Get-Content (Join-Path $script:AdvancedRoot 'Private/Get-AdvancedSecurityRegistryTargets.ps1') -Raw
            $targets | Should -Match 'Add-ManagedKey "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\\$version"'
            $restore = Get-Content (Join-Path $script:AdvancedRoot 'Private/Restore-AdvancedSecurityRegistryState.ps1') -Raw
            $restore | Should -Match 'Where-Object \{ -not \[bool\]\$_.KeyExisted \}'
            $restore | Should -Match 'Originally absent AdvancedSecurity key remains after restore'
        }

        It "Should not retain legacy administrative-share reconstruction restore" {
            $source = Get-Content (Join-Path $script:AdvancedRoot 'Public/Restore-AdvancedSecuritySettings.ps1') -Raw
            $source | Should -Not -Match 'function\s+Restore-AdminShares'
            $source | Should -Not -Match '\bNew-SmbShare\b'
            $source | Should -Match 'ValidateSet\(''AdvancedSecurity_FirewallPolicy'', ''PowerShellV2'', ''WiFiDirect_Adapters'', ''NetBIOS_Adapters''\)'
            $source | Should -Match "'PowerShellV2'\s*\{\s*return \[bool\]\(Restore-PowerShellV2" `
                -Because 'existing sealed v2.2.5 sessions must retain their exact restore path'
        }

        It "Should keep automated High-impact AdvancedSecurity restore non-interactive" {
            $rollback = Get-Content (Join-Path (Split-Path $script:AdvancedRoot -Parent | Split-Path -Parent) 'Core/Rollback.ps1') -Raw
            $restore = Get-Content (Join-Path $script:AdvancedRoot 'Public/Restore-AdvancedSecuritySettings.ps1') -Raw
            $rollback | Should -Match 'Restore-AdvancedSecurityRegistryState[\s\S]{0,180}-Confirm:\$false'
            $rollback | Should -Match 'Restore-AdvancedSecuritySettings[\s\S]{0,220}-Confirm:\$false'
            $restore | Should -Match 'Restore-FirewallPolicy -BackupFilePath \$BackupFilePath -Confirm:\$false'
        }

        It "Should load exact registry restore dependencies outside module import" {
            $restoreRegistry = Get-Content (Join-Path $script:AdvancedRoot 'Private/Restore-AdvancedSecurityRegistryState.ps1') -Raw
            $restoreRegistry | Should -Match "Command = 'Get-AdvancedSecuritySchema5RegistryTargets'.*File = 'Get-AdvancedSecuritySchema5RegistryTargets\.ps1'"
            $restoreRegistry | Should -Match "Command = 'Assert-AdvancedSecurityRegistrySnapshot'.*File = 'Assert-AdvancedSecurityRegistrySnapshot\.ps1'"
            $firstTargets = $restoreRegistry.IndexOf("Command = 'Get-AdvancedSecuritySchema5RegistryTargets'")
            $firstValidator = $restoreRegistry.IndexOf("Command = 'Assert-AdvancedSecurityRegistrySnapshot'")
            $firstValidationCall = $restoreRegistry.IndexOf('Assert-AdvancedSecurityRegistrySnapshot -Snapshot')
            $firstTargets | Should -BeLessThan $firstValidator
            $firstValidator | Should -BeLessThan $firstValidationCall
            $restoreRegistry | Should -Match 'Assert-AdvancedSecurityRegistrySnapshot -Snapshot \$snapshot -RestoreOnly'
            $restoreRegistry | Should -Not -Match 'Get-AdvancedSecurityRegistryTargets\s+`'
        }

        It 'Should restore Shields Up with NetSecurity GpoBoolean tokens rather than System.Boolean' {
            $restoreRegistry = Get-Content (Join-Path $script:AdvancedRoot 'Private/Restore-AdvancedSecurityRegistryState.ps1') -Raw
            $restoreRegistry | Should -Match '\$allowInboundRules\s*=\s*if\s*\(\$savedShieldsUpValue\s*-eq\s*0\)\s*\{\s*''True''\s*\}\s*else\s*\{\s*''False''\s*\}'
            $restoreRegistry | Should -Match '-AllowInboundRules\s+\$allowInboundRules'
            $restoreRegistry | Should -Not -Match '\$allowInboundRules\s*=\s*\(\$savedShieldsUpValue\s*-eq\s*0\)'
        }

        It 'Should freeze schema 5 restore targets independently of the current Apply inventory' {
            $frozen = Get-Content (Join-Path $script:AdvancedRoot 'Private/Get-AdvancedSecuritySchema5RegistryTargets.ps1') -Raw
            $validator = Get-Content (Join-Path $script:AdvancedRoot 'Private/Assert-AdvancedSecurityRegistrySnapshot.ps1') -Raw
            $rollback = Get-Content (Join-Path (Split-Path $script:AdvancedRoot -Parent | Split-Path -Parent) 'Core/Rollback.ps1') -Raw

            $frozen | Should -Match 'immutable registry-target contract for sealed schema-5'
            $frozen | Should -Not -Match '\bGet-AdvancedSecurityRegistryTargets\b'
            $validator | Should -Match 'if \(\$RestoreOnly\)[\s\S]{0,160}''Get-AdvancedSecuritySchema5RegistryTargets'''
            $validator | Should -Match 'else \{[\s\S]{0,100}''Get-AdvancedSecurityRegistryTargets'''
            $rollback | Should -Match 'Get-AdvancedSecuritySchema5RegistryTargets\.ps1'
            $rollback | Should -Match 'Assert-AdvancedSecurityRegistrySnapshot -Snapshot \$json -RestoreOnly'
        }

        It 'Should require a schema bump whenever the live target inventory diverges from frozen schema 5' {
            InModuleScope AdvancedSecurity {
                foreach ($mask in 0..1023) {
                    $arguments = @{
                        SkipFirewallLayer = [bool]($mask -band 1)
                        DisableRDP = [bool]($mask -band 2)
                        AdminSharesDisabled = [bool]($mask -band 4)
                        DisableWirelessDisplayCompletely = [bool]($mask -band 8)
                        DisableDiscoveryProtocolsCompletely = [bool]($mask -band 16)
                        DisableIPv6Completely = [bool]($mask -band 32)
                        EnableFirewallShieldsUp = [bool]($mask -band 64)
                        RdpHostSupported = [bool]($mask -band 128)
                        ManagedPolicySupported = [bool]($mask -band 256)
                        WirelessDisplaySupported = [bool]($mask -band 512)
                    }
                    $live = @(Get-AdvancedSecurityRegistryTargets @arguments | ForEach-Object {
                            "$([string]$_.Path)`0$([string]$_.Name)`0$([bool]$_.KeyOnly)"
                        })
                    $frozen = @(Get-AdvancedSecuritySchema5RegistryTargets @arguments | ForEach-Object {
                            "$([string]$_.Path)`0$([string]$_.Name)`0$([bool]$_.KeyOnly)"
                        })
                    if (($live | ConvertTo-Json -Compress) -cne
                        ($frozen | ConvertTo-Json -Compress)) {
                        throw "Live AdvancedSecurity inventory diverged from frozen schema 5 for decision mask $mask; bump the snapshot schema before release"
                    }
                }
            }
        }

        It 'Should validate a sealed schema 5 restore without consulting the current Apply target helper' {
            InModuleScope AdvancedSecurity {
                $targets = @(Get-AdvancedSecuritySchema5RegistryTargets `
                    -SkipFirewallLayer:$false `
                    -DisableRDP:$false `
                    -AdminSharesDisabled:$false `
                    -DisableWirelessDisplayCompletely:$false `
                    -DisableDiscoveryProtocolsCompletely:$false `
                    -DisableIPv6Completely:$false `
                    -EnableFirewallShieldsUp:$false `
                    -RdpHostSupported:$true `
                    -ManagedPolicySupported:$true `
                    -WirelessDisplaySupported:$true)
                $entries = @($targets | ForEach-Object {
                        [PSCustomObject]@{
                            Path       = [string]$_.Path
                            Name       = [string]$_.Name
                            KeyOnly    = [bool]$_.KeyOnly
                            KeyExisted = $false
                            Exists     = $false
                            Value      = $null
                            Type       = $null
                        }
                    })
                $snapshot = [PSCustomObject]@{
                    SchemaVersion                    = 5
                    SkipFirewallLayer                = $false
                    DisableRDP                      = $false
                    AdminSharesDisabled             = $false
                    DisableUPnP                     = $true
                    DisableWirelessDisplayCompletely = $false
                    DisableDiscoveryProtocolsCompletely = $false
                    DisableIPv6Completely           = $false
                    EnableFirewallShieldsUp          = $false
                    RdpHostSupported                 = $true
                    ManagedPolicySupported           = $true
                    WirelessDisplaySupported         = $true
                    EditionFamily                    = 'Professional'
                    CapturedAt                       = [DateTimeOffset]::UtcNow.ToString('o')
                    WinInetUsers                     = @()
                    TargetCount                      = $entries.Count
                    Entries                          = $entries
                }

                Mock Get-AdvancedSecurityRegistryTargets { throw 'current inventory must not be read during restore' }
                $validated = Assert-AdvancedSecurityRegistrySnapshot -Snapshot $snapshot -RestoreOnly
                $validated.TargetCount | Should -Be $entries.Count
                { Assert-AdvancedSecurityRegistrySnapshot -Snapshot $snapshot } |
                    Should -Throw '*current inventory must not be read during restore*'
            }
        }

        It "Should compare complete firewall policy semantics without mounting sealed artifacts" {
            $stateHelper = Get-Content (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityFirewallPolicyState.ps1') -Raw
            $backup = Get-Content (Join-Path $script:AdvancedRoot 'Private/Backup-AdvancedSecuritySettings.ps1') -Raw
            $prestate = Get-Content (Join-Path $script:AdvancedRoot 'Private/Assert-AdvancedSecurityPrestate.ps1') -Raw
            $restore = Get-Content (Join-Path $script:AdvancedRoot 'Public/Restore-AdvancedSecuritySettings.ps1') -Raw
            $stateHelper | Should -Match 'Copy-Item -LiteralPath \$resolvedPath -Destination \$workingCopyPath'
            $stateHelper | Should -Match 'GetSubKeyNames'
            $stateHelper | Should -Match 'GetValueKind'
            $stateHelper | Should -Match 'DoNotExpandEnvironmentNames'
            $stateHelper | Should -Match "Kind = 'Key'"
            $stateHelper | Should -Match 'Assert-AdvancedSecurityFirewallPolicyEquivalent'
            $stateHelper | Should -Match "Join-Path \`$env:SystemRoot 'System32\\reg\.exe'"
            $stateHelper | Should -Match '\[Diagnostics\.ProcessStartInfo\]::new\(\)'
            $stateHelper | Should -Match 'foreach \(\$attempt in 1\.\.5\)'
            $stateHelper | Should -Match 'Test-AdvancedSecurityTemporaryFirewallHive'
            $stateHelper | Should -Not -Match '&\s+reg\.exe'
            foreach ($source in @($backup, $prestate, $restore)) {
                $source | Should -Match 'Assert-AdvancedSecurityFirewallPolicyEquivalent'
                $source | Should -Not -Match 'Get-FileHash[\s\S]{0,240}Firewall'
            }
        }

        It "Should not restart an unbacked Windows Update service" {
            $source = Get-Content (Join-Path $script:AdvancedRoot 'Private/Set-WindowsUpdate.ps1') -Raw
            $source | Should -Not -Match '\bRestart-Service\b'
        }

        It "Should keep optional updates user-selected and preserve external product update enrollment" {
            $config = Get-Content (Join-Path $script:AdvancedRoot 'Config/WindowsUpdate.json') -Raw | ConvertFrom-Json
            [int]$config.TotalRegistryKeys | Should -Be 3
            [int]$config.Settings.'1_OptionalUpdatesPolicy'.Values.SetAllowOptionalContent.Value | Should -Be 3
            [int]$config.Settings.'2_ContinuousInnovationPreference'.Values.IsContinuousInnovationOptedIn.Value | Should -Be 0
            $config.Settings.PSObject.Properties.Name | Should -Not -Contain '3_MicrosoftUpdate'
            @($config.Settings.PSObject.Properties | ForEach-Object {
                    $_.Value.Values.PSObject.Properties.Name
                }) | Should -Not -Contain 'AllowMUUpdateService'

            $targets = Get-Content (Join-Path $script:AdvancedRoot 'Private/Get-AdvancedSecurityRegistryTargets.ps1') -Raw
            $apply = Get-Content (Join-Path $script:AdvancedRoot 'Private/Set-WindowsUpdate.ps1') -Raw
            $test = Get-Content (Join-Path $script:AdvancedRoot 'Private/Test-WindowsUpdate.ps1') -Raw
            $invoke = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $verifier = Get-Content (Join-Path (Split-Path $script:AdvancedRoot -Parent | Split-Path -Parent) 'Tools/Verify-Complete-Hardening.ps1') -Raw
            foreach ($source in @($targets, $verifier)) {
                $source | Should -Not -Match 'AllowMUUpdateService'
            }
            $verifier | Should -Match 'SetAllowOptionalContent"; Expected = 3'
            $verifier | Should -Match 'IsContinuousInnovationOptedIn"; Expected = 0'
            $apply | Should -Match 'no registry write was attempted for \$valueName'
            $test | Should -Match "GetValueNames\(\) -contains 'CIOptinModified'"
            $test | Should -Match 'NotCheckedCount = \$settingsNotChecked'
            $invoke | Should -Match 'SettingsNotChecked = \$settingsRuntimeNotChecked'
            $invoke | Should -Match '\$settingsApplied = if \(\$hasFailures\) \{ 0 \} else \{ \$settingsAttempted - \$settingsRuntimeNotChecked \}'
        }

        It "Should classify only a stamped manual Windows Update opt-in as NotChecked" {
            InModuleScope AdvancedSecurity {
                function Get-TestRegistryKey {
                    param([hashtable]$Values)
                    $key = [PSCustomObject]@{ Values = $Values }
                    $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @($this.Values.Keys) }
                    $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value { param($Name) $null = $Name; 'DWord' }
                    $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($Name) $this.Values[$Name] }
                    return $key
                }
                $script:WindowsUpdateTestKeys = @{
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' = Get-TestRegistryKey @{ SetAllowOptionalContent = 3 }
                    'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' = Get-TestRegistryKey @{
                        IsContinuousInnovationOptedIn = 1
                        CIOptinModified = 1784342400000
                    }
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' = Get-TestRegistryKey @{ DODownloadMode = 0 }
                }
                Mock Test-Path { $true }
                Mock Get-Item { $script:WindowsUpdateTestKeys[[string]$LiteralPath] }

                $result = Test-WindowsUpdate -ManagedPoliciesSupported $true
                $result.Compliant | Should -BeTrue
                $result.ConfiguredCount | Should -Be 2
                $result.NotCheckedCount | Should -Be 1
                $result.FailedCount | Should -Be 0
                $result.TotalCount | Should -Be 3
                $result.Status | Should -Match 'user choice NotChecked'
            }
        }

        It "Should keep an unstamped Windows Update value 1 as a hard failure" {
            InModuleScope AdvancedSecurity {
                function Get-TestRegistryKey {
                    param([hashtable]$Values)
                    $key = [PSCustomObject]@{ Values = $Values }
                    $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @($this.Values.Keys) }
                    $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value { param($Name) $null = $Name; 'DWord' }
                    $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($Name) $this.Values[$Name] }
                    return $key
                }
                $script:WindowsUpdateTestKeys = @{
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' = Get-TestRegistryKey @{ SetAllowOptionalContent = 3 }
                    'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' = Get-TestRegistryKey @{ IsContinuousInnovationOptedIn = 1 }
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' = Get-TestRegistryKey @{ DODownloadMode = 0 }
                }
                Mock Test-Path { $true }
                Mock Get-Item { $script:WindowsUpdateTestKeys[[string]$LiteralPath] }

                $result = Test-WindowsUpdate -ManagedPoliciesSupported $true
                $result.Compliant | Should -BeFalse
                $result.ConfiguredCount | Should -Be 2
                $result.NotCheckedCount | Should -Be 0
                $result.FailedCount | Should -Be 1
                $result.TotalCount | Should -Be 3
                $result.Status | Should -Be 'Incomplete'
            }
        }

        It "Should use stable module-owned risky-port firewall rule names" {
            $source = Get-Content (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityFirewallRules.ps1') -Raw
            foreach ($name in @(
                'NoID-Block-LLMNR-UDP-5355','NoID-Block-NetBIOS-UDP-137',
                'NoID-Block-NetBIOS-UDP-138','NoID-Block-NetBIOS-TCP-139',
                'NoID-Block-SSDP-UDP-1900','NoID-Block-UPnP-TCP-2869'
            )) { $source | Should -Match ([regex]::Escape($name)) }
        }

        It "Should account for 16 stable rules plus the Shields Up registry target" {
            $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $counts = Get-Content (Join-Path $repo 'Config/SettingsCounts.json') -Raw | ConvertFrom-Json
            [int]$counts.modules.AdvancedSecurity.firewall | Should -Be 17
            . (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityFirewallRules.ps1')
            @(Get-AdvancedSecurityFirewallDefinitions).Count | Should -Be 16
        }

        It 'pins every firewall rule tuple independently of the definitions under test' {
            # Apply creates each rule from its definition and verifies it against
            # the SAME definition, and the complete-hardening verifier re-checks
            # against the same source again - so changing Port 138 to 1338, or an
            # Inbound blocker to Outbound, was applied, verified and attested with
            # no dissenting authority anywhere. This literal table is that
            # authority: the definition file can no longer change alone.
            . (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityFirewallRules.ps1')
            $definitions = @(Get-AdvancedSecurityFirewallDefinitions)

            $expected = @{
                'NoID-Block-LLMNR-UDP-5355'      = @('Inbound',  'UDP', 'LocalPort',  '5355', 'Any',    'Base',        'RiskyPorts')
                'NoID-Block-NetBIOS-UDP-137'     = @('Inbound',  'UDP', 'LocalPort',  '137',  'Any',    'Base',        'RiskyPorts')
                'NoID-Block-NetBIOS-UDP-138'     = @('Inbound',  'UDP', 'LocalPort',  '138',  'Any',    'Base',        'RiskyPorts')
                'NoID-Block-NetBIOS-TCP-139'     = @('Inbound',  'TCP', 'LocalPort',  '139',  'Any',    'Base',        'RiskyPorts')
                'NoID-Block-SSDP-UDP-1900'       = @('Inbound',  'UDP', 'LocalPort',  '1900', 'Any',    'UPnP',        'RiskyPorts')
                'NoID-Block-UPnP-TCP-2869'       = @('Inbound',  'TCP', 'LocalPort',  '2869', 'Any',    'UPnP',        'RiskyPorts')
                'NoID-Block-AdminShares-TCP-445' = @('Inbound',  'TCP', 'LocalPort',  '445',  'Public', 'AdminShares', 'AdminShares')
                'NoID-Block-Finger-TCP-79'       = @('Outbound', 'TCP', 'RemotePort', '79',   'Any',    'Base',        'Finger')
                'NoID-Block-WSD-UDP-3702'        = @('Inbound',  'UDP', 'LocalPort',  '3702', 'Any',    'Discovery',   'Discovery')
                'NoID-Block-WSD-TCP-5357'        = @('Inbound',  'TCP', 'LocalPort',  '5357', 'Any',    'Discovery',   'Discovery')
                'NoID-Block-WSD-TCP-5358'        = @('Inbound',  'TCP', 'LocalPort',  '5358', 'Any',    'Discovery',   'Discovery')
                'NoID-Block-mDNS-UDP-5353'       = @('Inbound',  'UDP', 'LocalPort',  '5353', 'Any',    'Discovery',   'Discovery')
                'NoID-Block-Miracast-TCP-7236'   = @('Inbound',  'TCP', 'LocalPort',  '7236', 'Any',    'Miracast',    'Miracast')
                'NoID-Block-Miracast-TCP-7250'   = @('Inbound',  'TCP', 'LocalPort',  '7250', 'Any',    'Miracast',    'Miracast')
                'NoID-Block-Miracast-UDP-7236'   = @('Inbound',  'UDP', 'LocalPort',  '7236', 'Any',    'Miracast',    'Miracast')
                'NoID-Block-Miracast-UDP-7250'   = @('Inbound',  'UDP', 'LocalPort',  '7250', 'Any',    'Miracast',    'Miracast')
            }

            $definitions.Count | Should -Be $expected.Count
            foreach ($definition in $definitions) {
                $name = [string]$definition.Name
                $expected.ContainsKey($name) | Should -BeTrue -Because "rule $name must be one of the 16 declared identities"
                $tuple = $expected[$name]
                [string]$definition.Direction | Should -BeExactly $tuple[0] -Because "the direction of $name"
                [string]$definition.Protocol | Should -BeExactly $tuple[1] -Because "the protocol of $name"
                [string]$definition.PortProperty | Should -BeExactly $tuple[2] -Because "the port property of $name"
                [string]$definition.Port | Should -BeExactly $tuple[3] -Because "the port of $name"
                [string]$definition.Profile | Should -BeExactly $tuple[4] -Because "the profile of $name"
                [string]$definition.Group | Should -BeExactly $tuple[5] -Because "the group of $name"
                [string]$definition.Feature | Should -BeExactly $tuple[6] -Because "the feature of $name"

                # Self-consistency: the protocol and port a rule's NAME advertises
                # must be the protocol and port it enforces.
                if ($name -match '-(TCP|UDP)-(\d+)$') {
                    [string]$definition.Protocol | Should -BeExactly $Matches[1] -Because "$name must enforce the protocol in its own name"
                    [string]$definition.Port | Should -BeExactly $Matches[2] -Because "$name must enforce the port in its own name"
                }
            }
        }

        It 'Should verify both Shields Up enable and disable through the effective firewall profile' {
            $source = Get-Content (Join-Path $script:AdvancedRoot 'Private/Set-FirewallShieldsUp.ps1') -Raw
            ([regex]::Matches($source, 'Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore')).Count |
                Should -BeGreaterOrEqual 3
            $source | Should -Match 'Shields Up disable registry post-apply mismatch'
            $source | Should -Match 'Shields Up disable effective firewall profile verification failed'
        }

        It "Should recreate and verify every owned firewall rule from one exact schema" {
            $firewallSource = Get-Content (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityFirewallRules.ps1') -Raw
            $firewallSource | Should -Match 'Remove-NetFirewallRule'
            $firewallSource | Should -Match 'Get-NetFirewallAddressFilter'
            $firewallSource | Should -Match 'Get-NetFirewallApplicationFilter'
            $firewallSource | Should -Match 'Get-NetFirewallServiceFilter'
            $firewallSource | Should -Match 'Get-NetFirewallInterfaceTypeFilter'
            foreach ($applyFile in @(
                    'Disable-RiskyPorts.ps1', 'Disable-AdminShares.ps1', 'Block-FingerProtocol.ps1',
                    'Set-DiscoveryProtocolsSecurity.ps1', 'Set-WirelessDisplaySecurity.ps1'
                )) {
                (Get-Content (Join-Path $script:AdvancedRoot "Private/$applyFile") -Raw) |
                    Should -Match 'Set-AdvancedSecurityFirewallRuleDefinition'
            }
        }

        It "Should verify identically from the bulk filter snapshot without any live firewall query" {
            # StrictMode mirrors the release build gate, which runs the whole
            # suite under Set-StrictMode Latest; a silently-null .Count on an
            # enumerated one-element list must fail here, not first in the gate.
            Set-StrictMode -Version Latest
            . (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityFirewallRules.ps1')
            $definition = @(Get-AdvancedSecurityFirewallDefinitions)[0]
            $rule = [PSCustomObject]@{
                Name = $definition.Name; InstanceID = $definition.Name
                DisplayName = $definition.DisplayName; Description = $definition.Description
                Enabled = 'True'; Direction = $definition.Direction; Action = 'Block'
                Profile = $definition.Profile; EdgeTraversalPolicy = 'Block'
            }
            $cache = @{
                Port          = @{ $definition.Name = [PSCustomObject]@{ InstanceID = $definition.Name; Protocol = $definition.Protocol; LocalPort = $definition.Port; RemotePort = 'Any' } }
                Address       = @{ $definition.Name = [PSCustomObject]@{ InstanceID = $definition.Name; LocalAddress = 'Any'; RemoteAddress = 'Any' } }
                Application   = @{ $definition.Name = [PSCustomObject]@{ InstanceID = $definition.Name; Program = 'Any' } }
                Service       = @{ $definition.Name = [PSCustomObject]@{ InstanceID = $definition.Name; Service = 'Any' } }
                Interface     = @{ $definition.Name = [PSCustomObject]@{ InstanceID = $definition.Name; InterfaceAlias = 'Any' } }
                InterfaceType = @{ $definition.Name = [PSCustomObject]@{ InstanceID = $definition.Name; InterfaceType = 'Any' } }
            }
            Mock Get-NetFirewallRule { throw 'live rule query must not run in snapshot mode' }
            Mock Get-NetFirewallPortFilter { throw 'live filter query must not run in snapshot mode' }

            $result = Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition -RuleSet @($rule) -FilterCache $cache
            $result.Compliant | Should -BeTrue
            $result.Mismatches | Should -BeNullOrEmpty

            # A wrong filter value must be detected - proves the per-filter
            # value checks actually execute on the snapshot path.
            $wrongCache = @{}
            foreach ($cacheKey in $cache.Keys) { $wrongCache[$cacheKey] = $cache[$cacheKey] }
            $wrongCache.Port = @{ $definition.Name = [PSCustomObject]@{ InstanceID = $definition.Name; Protocol = $definition.Protocol; LocalPort = '65000'; RemotePort = 'Any' } }
            $wrongResult = Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition -RuleSet @($rule) -FilterCache $wrongCache
            $wrongResult.Compliant | Should -BeFalse
            ($wrongResult.Mismatches -join '; ') | Should -Match 'LocalPort=65000'

            $missing = Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition -RuleSet @() -FilterCache $cache
            $missing.Compliant | Should -BeFalse
            $missing.Mismatches[0] | Should -Match 'found 0'

            { Test-AdvancedSecurityFirewallRuleDefinition -Definition $definition -RuleSet @($rule) } |
                Should -Throw '*RuleSet and FilterCache together*'
        }

        It "Should build the real bulk filter cache without null entries and equal to the association queries" {
            . (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityFirewallRules.ps1')
            # Store-wide enumeration can be access-denied without elevation while
            # association queries still work; the verifier falls back to the live
            # path there, so this equivalence proof only applies to sessions that
            # can read the bulk snapshot. Skip on THAT and nothing else: catching
            # every exception meant a genuinely broken
            # Get-AdvancedSecurityFirewallFilterCache - the only thing this test
            # proves - was reported as a green skip.
            try {
                $cache = Get-AdvancedSecurityFirewallFilterCache
            }
            catch {
                # Skip ONLY on a proven access-denied from the firewall store, and
                # decide that from the CIM/Win32 status code rather than from a
                # localized message. Catching everything turned a genuinely broken
                # Get-AdvancedSecurityFirewallFilterCache - the single thing this
                # test proves - into a green skip.
                $cacheError = $_.Exception
                $accessDenied = $false
                while ($cacheError) {
                    if ($cacheError -is [System.UnauthorizedAccessException]) { $accessDenied = $true; break }
                    if ($cacheError -is [Microsoft.Management.Infrastructure.CimException] -and
                        [int]$cacheError.NativeErrorCode -eq 2) { $accessDenied = $true; break }  # AccessDenied
                    if ($cacheError.PSObject.Properties['NativeErrorCode'] -and
                        [int]$cacheError.NativeErrorCode -eq 5) { $accessDenied = $true; break }  # ERROR_ACCESS_DENIED
                    $cacheError = $cacheError.InnerException
                }
                if (-not $accessDenied) { throw }
                Set-ItResult -Skipped -Because "store-wide filter enumeration denied in this session: $($_.Exception.Message)"
                return
            }
            @($cache.Keys) | Sort-Object | Should -Be @('Address', 'Application', 'Interface', 'InterfaceType', 'Port', 'Service')
            foreach ($filterKey in $cache.Keys) {
                foreach ($entry in $cache[$filterKey].GetEnumerator()) {
                    $filters = @($entry.Value)
                    $filters.Count | Should -BeGreaterThan 0
                    @($filters | Where-Object { $null -eq $_ }).Count | Should -Be 0
                }
            }
            # Cross-check cache lookups against live association queries for a
            # few real rules - the exact equivalence the verifier relies on
            # (and the one thing a hand-built mock cache cannot prove).
            foreach ($sampleRule in @(Get-NetFirewallRule | Select-Object -First 3)) {
                $ruleId = [string]$sampleRule.InstanceID
                $cachedCount = if ($cache.Port.ContainsKey($ruleId)) { @($cache.Port[$ruleId]).Count } else { 0 }
                $cachedCount | Should -Be @($sampleRule | Get-NetFirewallPortFilter).Count
            }
        }

        It "Should preserve RDP state unless complete disable was explicitly selected" {
            $source = Get-Content (Join-Path $script:AdvancedRoot 'Private/Enable-RdpNLA.ps1') -Raw
            $verifier = Get-Content (Join-Path (Split-Path $script:AdvancedRoot -Parent | Split-Path -Parent) 'Tools/Verify-Complete-Hardening.ps1') -Raw
            $source | Should -Match 'RDP enable/disable state preserved'
            $source | Should -Match 'if \(\$DisableRDP\)[\s\S]+fDenyTSConnections'
            $source | Should -Not -Match "New-ItemProperty[^\r\n]+fDenyTSConnections[^\r\n]+Value 0"
            $verifier | Should -Match 'AdvancedSecurityDisableRDP'
            $verifier | Should -Match 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'
            $verifier | Should -Not -Match 'AllowedValues\s*=\s*@\(0,1\)'
        }

        It "Should bind registry and service backup targets to the exact option set" {
            $targets = Get-Content (Join-Path $script:AdvancedRoot 'Private/Get-AdvancedSecurityRegistryTargets.ps1') -Raw
            $backup = Get-Content (Join-Path $script:AdvancedRoot 'Private/Backup-AdvancedSecuritySettings.ps1') -Raw
            foreach ($decision in @(
                    'DisableRDP', 'AdminSharesDisabled', 'DisableWirelessDisplayCompletely',
                    'DisableDiscoveryProtocolsCompletely', 'DisableIPv6Completely', 'EnableFirewallShieldsUp'
                )) {
                $targets | Should -Match ([regex]::Escape("`$$decision"))
                $backup | Should -Match (('{0}\s*=\s*\[bool\]\${0}' -f $decision))
            }
            $backup | Should -Match '\$services = @\(''lmhosts''\)'
            $backup | Should -Match 'if \(\$DisableUPnP\).*SSDPSRV.*upnphost'
            $backup | Should -Match 'if \(\$WirelessDisplaySupported -and \$DisableWirelessDisplayCompletely\).*WFDSConMgrSvc'
            $backup | Should -Match 'if \(\$DisableDiscoveryProtocolsCompletely\).*FDResPub.*fdPHost'
        }

        It 'uses one authoritative Admin Shares decision from plan through verification' {
            $source = Get-Content (
                Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            @([regex]::Matches(
                    $source,
                    '\$adminSharesSelected\s*=\s*-not \(\$isDomainJoined')).Count | Should -Be 1
            $source | Should -Match '\$adminSharesDisabled\s*=\s*\[bool\]\$adminSharesSelected'
            $source | Should -Not -Match '\$adminSharesDisabled\s*=\s*-not \(\$isDomainJoined'
        }

        It "Should reconcile every selected live prestate immediately before sealing" {
            $backup = Get-Content (Join-Path $script:AdvancedRoot 'Private/Backup-AdvancedSecuritySettings.ps1') -Raw
            foreach ($proof in @(
                    'Service state changed during backup',
                    'Firewall policy changed while AdvancedSecurity backup was running',
                    'Wi-Fi Direct adapter inventory/state changed during backup',
                    'NetBIOS adapter inventory/state changed during backup',
                    'Interactive Explorer user changed during AdvancedSecurity backup',
                    'WinINet AutoDetect state changed during AdvancedSecurity backup',
                    'Managed registry prestate changed during AdvancedSecurity backup'
                )) {
                $backup | Should -Match ([regex]::Escape($proof))
            }
            $backup | Should -Match '\$currentInteractiveUsers = @\(\)[\s\S]{0,180}if \(\$null -ne \$currentInteractiveUser\)[\s\S]{0,180}\$currentInteractiveUsers = @\(\$currentInteractiveUser\)'
            $invoke = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $invoke | Should -Match 'Save-IncompleteModuleBackup -ModuleName ''AdvancedSecurity'''
        }

        It "Should keep NetBIOS hardening active when the firewall layer is skipped" {
            $apply = Get-Content (Join-Path $script:AdvancedRoot 'Private/Disable-RiskyPorts.ps1') -Raw
            $netbios = Get-Content (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityNetBIOS.ps1') -Raw
            $invoke = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $test = Get-Content (Join-Path $script:AdvancedRoot 'Private/Test-RiskyPorts.ps1') -Raw
            $apply | Should -Match 'SkipFirewallChanges'
            $apply | Should -Match 'Invoke-AdvancedSecurityNetBIOSDisable'
            $netbios | Should -Match 'SetTcpipNetbios'
            $netbios | Should -Match 'Get-NetAdapter -IncludeHidden'
            $netbios | Should -Match 'HardwareInterface'
            $netbios | Should -Match 'RegistryValueType'
            $invoke | Should -Match 'Disable-RiskyPorts[\s\S]{0,180}-SkipFirewallChanges:\$SkipFirewallLayer'
            $test | Should -Match 'SkipFirewallChecks'
            $test | Should -Match 'FirewallCheckState'
        }

        It "Should seal schema-2 typed NetBT state and retain legacy restore compatibility" {
            $helper = Get-Content (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityNetBIOS.ps1') -Raw
            $backup = Get-Content (Join-Path $script:AdvancedRoot 'Private/Backup-AdvancedSecuritySettings.ps1') -Raw
            $prestate = Get-Content (Join-Path $script:AdvancedRoot 'Private/Assert-AdvancedSecurityPrestate.ps1') -Raw
            $restore = Get-Content (Join-Path $script:AdvancedRoot 'Public/Restore-AdvancedSecuritySettings.ps1') -Raw
            $verifier = Get-Content (Join-Path (Split-Path $script:AdvancedRoot -Parent | Split-Path -Parent) 'Tools/Verify-Complete-Hardening.ps1') -Raw

            $helper | Should -Match 'SchemaVersion\s*=\s*2'
            $helper | Should -Match 'DoNotExpandEnvironmentNames'
            $helper | Should -Match 'RegistryKeyExisted'
            $helper | Should -Match 'RegistryValueExists'
            $helper | Should -Match 'Write-AdvancedSecurityNetBIOSRegistryValue'
            $helper | Should -Match 'Originally absent NetBIOS key gained unrelated state'
            $backup | Should -Match 'Get-AdvancedSecurityNetBIOSState'
            $prestate | Should -Match 'Test-AdvancedSecurityNetBIOSStateEqual'
            $restore | Should -Match "SchemaVersion' -and[\s\S]{0,180}Restore-AdvancedSecurityNetBIOSState"
            $restore | Should -Match 'Legacy version-1 array artifacts remain readable'
            $verifier | Should -Match 'Test-AdvancedSecurityNetBIOSDisabled'
        }

        It "Should never fall back from a sealed NetBIOS SettingID to a reused adapter index" {
            $restore = Get-Content (Join-Path $script:AdvancedRoot 'Public/Restore-AdvancedSecuritySettings.ps1') -Raw
            $restore | Should -Match 'Expected exactly one adapter for SettingID'
            $restore | Should -Match 'if \(\$hasStableIdentity\)[\s\S]+else \{[\s\S]+legacyMatches'
        }

        It "Should accept only exact REG_DWORD 255 for the selected IPv6 component-disable state" {
            $source = Get-Content (Join-Path $script:AdvancedRoot 'Private/Test-IPv6Security.ps1') -Raw
            $source | Should -Match "GetValueKind\('DisabledComponents'\).*'DWord'"
            $source | Should -Match '\[int\]\$actual -eq 255[\s\S]{0,260}Pass\s*=\s*\$true[\s\S]{0,100}Compliant\s*=\s*\$true'
            $source | Should -Not -Match 'DisabledComponents -gt 0[\s\S]{0,260}Compliant\s*=\s*\$true'
            $source | Should -Match 'complete mitm6 prevention are not asserted'
        }

        It "Should not tattoo the obsolete Windows 11 WDigest policy" {
            $targets = Get-Content (Join-Path $script:AdvancedRoot 'Private/Get-AdvancedSecurityRegistryTargets.ps1') -Raw
            $invoke = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $verifier = Get-Content (Join-Path (Split-Path $script:AdvancedRoot -Parent | Split-Path -Parent) 'Tools/Verify-Complete-Hardening.ps1') -Raw
            $targets | Should -Not -Match 'UseLogonCredential|WDigest'
            $invoke | Should -Not -Match 'Set-WDigestProtection|WDigest Protection'
            $verifier | Should -Not -Match 'UseLogonCredential|WDigest Disabled'
            (Join-Path $script:AdvancedRoot 'Private/Set-WDigestProtection.ps1') | Should -Not -Exist
            (Join-Path $script:AdvancedRoot 'Private/Test-WDigest.ps1') | Should -Not -Exist
        }

        It "Should bind Home edition applicability into Apply, BAVR schema 5 and complete verification" {
            $applicability = Get-Content (Join-Path $script:AdvancedRoot 'Private/Get-AdvancedSecurityApplicability.ps1') -Raw
            $targets = Get-Content (Join-Path $script:AdvancedRoot 'Private/Get-AdvancedSecurityRegistryTargets.ps1') -Raw
            $backup = Get-Content (Join-Path $script:AdvancedRoot 'Private/Backup-AdvancedSecuritySettings.ps1') -Raw
            $validator = Get-Content (Join-Path $script:AdvancedRoot 'Private/Assert-AdvancedSecurityRegistrySnapshot.ps1') -Raw
            $invoke = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $verifier = Get-Content (Join-Path (Split-Path $script:AdvancedRoot -Parent | Split-Path -Parent) 'Tools/Verify-Complete-Hardening.ps1') -Raw

            $applicability | Should -Match 'OperatingSystemSKU'
            $applicability | Should -Match 'RdpHostSupported\s*=\s*\$family -in @\(''Professional'', ''Enterprise'', ''Education''\)'
            foreach ($decision in @('RdpHostSupported', 'ManagedPolicySupported', 'WirelessDisplaySupported')) {
                $targets | Should -Match ([regex]::Escape("`$$decision"))
                $backup | Should -Match (('{0}\s*=\s*\[bool\]\${0}' -f $decision))
                $validator | Should -Match ([regex]::Escape("`$Snapshot.$decision"))
                $invoke | Should -Match ([regex]::Escape("-$decision`:$" + $decision.Substring(0,1).ToLowerInvariant() + $decision.Substring(1)))
            }
            $backup | Should -Match 'SchemaVersion\s*=\s*5'
            $validator | Should -Match 'SchemaVersion -ne 5'
            $verifier | Should -Match "CheckState='NotApplicable'"
        }

        It 'Should own only the documented WPAD controls and preserve unrelated proxy state' {
            $targets = Get-Content (Join-Path $script:AdvancedRoot 'Private/Get-AdvancedSecurityRegistryTargets.ps1') -Raw
            $helper = Get-Content (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityWinInet.ps1') -Raw
            $applyPath = Join-Path $script:AdvancedRoot 'Private/Disable-WPAD.ps1'
            $apply = Get-Content $applyPath -Raw
            $test = Get-Content (Join-Path $script:AdvancedRoot 'Private/Test-WPAD.ps1') -Raw
            $restore = Get-Content (Join-Path $script:AdvancedRoot 'Private/Restore-AdvancedSecurityRegistryState.ps1') -Raw
            $applyTokens = $null
            $applyParseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile(
                $applyPath,
                [ref]$applyTokens,
                [ref]$applyParseErrors
            )
            @($applyParseErrors).Count | Should -Be 0
            $applyCode = @($applyTokens | Where-Object Kind -notin @('Comment', 'NewLine') |
                ForEach-Object Text) -join ' '

            $targets | Should -Match "WinHttp' 'DisableWpad'"
            $targets | Should -Not -Match 'WpadOverride|DefaultConnectionSettings|SavedLegacySettings|HKU:'
            $applyCode | Should -Not -Match 'WpadOverride|New-ItemProperty\s+.*?-Name\s+[''"]AutoDetect|HKU:\\\.DEFAULT'
            $apply | Should -Match 'Undocumented scalar AutoDetect/WpadOverride values and HKU\\\.DEFAULT are'
            $helper | Should -Match 'InternetOptionPerConnectionOption = 75'
            $helper | Should -Match 'InternetPerConnFlagsUi = 10'
            $helper | Should -Match "ValidateSet\('Query', 'SetAutoDetect'\)"
            $helper | Should -Match 'BeforeFlags -band \[uint32\]4294967287'
            $helper | Should -Match 'Get-CimInstance -ClassName Win32_Process'
            $helper | Should -Match 'MethodName GetOwnerSid'
            $helper | Should -Match 'MethodName GetOwner'
            $helper | Should -Match 'ownerSid.ReturnValue -ne 0'
            $helper | Should -Match 'owner.ReturnValue -ne 0'
            $helper | Should -Match 'after 3 attempts'
            $helper | Should -Not -Match 'Get-Process -Name explorer -IncludeUserName'
            $helper | Should -Match "temporaryOutputPath = \`$OutputPath \+ '\.tmp'"
            $helper | Should -Match 'LastTaskResult -ne 0'
            foreach ($source in @($apply, $test)) {
                $source | Should -Match '\$users = @\(\)[\s\S]{0,160}\$users = @\(\$WinInetUsers\)[\s\S]{0,220}\$users = @\(\$currentUser\)'
                $source | Should -Not -Match '\$users = if \('
            }
            $restore | Should -Match 'Operation SetAutoDetect'
            $restore | Should -Match 'WinINet AutoDetect pre-state not restored'
            $restore | Should -Match 'Write-Log -Level WARNING'
            $restore | Should -Match 'continue'
            $restore | Should -Not -Match 'DefaultConnectionSettings|SavedLegacySettings'
        }

        It 'Should keep the WinINet user worker bounded without racing the caller deadline' {
            $helper = Get-Content (Join-Path $script:AdvancedRoot 'Private/AdvancedSecurityWinInet.ps1') -Raw
            $helper | Should -Match '\[ValidateRange\(5, 120\)\][\s\S]{0,80}\[int\]\$TimeoutSeconds\s*=\s*120'
            $helper | Should -Match '\$schedulerExecutionLimitSeconds\s*=\s*\[int\]\$TimeoutSeconds\s*\+\s*5'
            $helper | Should -Match '-ExecutionTimeLimit\s+\(New-TimeSpan -Seconds \$schedulerExecutionLimitSeconds\)'
            $helper | Should -Match '\$deadline\s*=\s*\[DateTime\]::UtcNow\.AddSeconds\(\$TimeoutSeconds\)'
            $helper | Should -Not -Match '-ExecutionTimeLimit\s+\(New-TimeSpan -Seconds \$TimeoutSeconds\)'
        }

        It 'Should reconcile preview/apply accounting for Pro, Home, and firewall-skip decisions' {
            InModuleScope AdvancedSecurity {
                $common = @{
                    SecurityProfile='Balanced'; DisableRDP=$false; AdminSharesSelected=$true
                    DisableUPnP=$false; DisableWirelessDisplayCompletely=$false
                    DisableDiscoveryProtocolsCompletely=$false; DisableIPv6Completely=$false
                    DeclaredCount=60; FirewallDeclaredCount=17
                }
                $pro = Get-AdvancedSecurityDecisionAccounting @common `
                    -SkipFirewallLayer $false -RdpHostSupported $true `
                    -ManagedPolicySupported $true -WirelessDisplaySupported $true
                ($pro.Attempted + $pro.Skipped + $pro.NotApplicable + $pro.NotSelected) | Should -Be 60
                $pro.NotApplicable | Should -Be 0

                $missingUnselectedSsdp = Get-AdvancedSecurityDecisionAccounting @common `
                    -SkipFirewallLayer $false -RdpHostSupported $true `
                    -ManagedPolicySupported $true -WirelessDisplaySupported $true `
                    -SsdpSrvPresent $false
                $missingUnselectedSsdp.Attempted | Should -Be $pro.Attempted
                $missingUnselectedSsdp.NotApplicable | Should -Be 1
                $missingUnselectedSsdp.NotSelected | Should -Be ($pro.NotSelected - 1)
                $missingUnselectedSsdp.RuntimeNotApplicableNotSelected | Should -Be 1

                $missingUnselectedOptionalRuntime = Get-AdvancedSecurityDecisionAccounting @common `
                    -SkipFirewallLayer $false -RdpHostSupported $true `
                    -ManagedPolicySupported $true -WirelessDisplaySupported $true `
                    -FdResPubPresent $false -WfdServicePresent $false -WfdAdapterPresent $false
                $missingUnselectedOptionalRuntime.Attempted | Should -Be $pro.Attempted
                $missingUnselectedOptionalRuntime.NotApplicable | Should -Be 3
                $missingUnselectedOptionalRuntime.NotSelected | Should -Be ($pro.NotSelected - 3)
                $missingUnselectedOptionalRuntime.RuntimeNotApplicableNotSelected | Should -Be 3

                $homeAccounting = Get-AdvancedSecurityDecisionAccounting @common `
                    -SkipFirewallLayer $false -RdpHostSupported $false `
                    -ManagedPolicySupported $false -WirelessDisplaySupported $false
                ($homeAccounting.Attempted + $homeAccounting.Skipped + $homeAccounting.NotApplicable + $homeAccounting.NotSelected) | Should -Be 60
                $homeAccounting.NotApplicable | Should -Be 18

                $skip = Get-AdvancedSecurityDecisionAccounting @common `
                    -SkipFirewallLayer $true -RdpHostSupported $true `
                    -ManagedPolicySupported $true -WirelessDisplaySupported $true
                ($skip.Attempted + $skip.Skipped + $skip.NotApplicable + $skip.NotSelected) | Should -Be 60
                $skip.Skipped | Should -Be 17
                $skip.SelectedFirewall | Should -Be 0
            }
        }

        It 'Should reject an equal-count decision inventory whose registry identities drift' {
            InModuleScope AdvancedSecurity {
                Mock Get-AdvancedSecurityRegistryTargets { @() }
                {
                    Get-AdvancedSecurityDecisionAccounting `
                        -SecurityProfile Balanced -SkipFirewallLayer $false `
                        -DisableRDP $false -AdminSharesSelected $true -DisableUPnP $false `
                        -DisableWirelessDisplayCompletely $false `
                        -DisableDiscoveryProtocolsCompletely $false -DisableIPv6Completely $false `
                        -RdpHostSupported $true -ManagedPolicySupported $true `
                        -WirelessDisplaySupported $true -DeclaredCount 60 -FirewallDeclaredCount 17
                } | Should -Throw '*decision/registry inventory identity drift*'
            }
        }

        It 'Should remove PowerShell v2 from new runs while preserving historical exact restore' {
            $invoke = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $runtime = Get-Content (Join-Path $script:AdvancedRoot 'Private/Get-AdvancedSecurityRuntimeApplicability.ps1') -Raw
            $backup = Get-Content (Join-Path $script:AdvancedRoot 'Private/Backup-AdvancedSecuritySettings.ps1') -Raw
            $test = Get-Content (Join-Path $script:AdvancedRoot 'Public/Test-AdvancedSecurity.ps1') -Raw
            $verifier = Get-Content (Join-Path (Split-Path $script:AdvancedRoot -Parent | Split-Path -Parent) 'Tools/Verify-Complete-Hardening.ps1') -Raw
            $restore = Get-Content (Join-Path $script:AdvancedRoot 'Public/Restore-AdvancedSecuritySettings.ps1') -Raw
            foreach ($source in @($invoke, $runtime, $backup, $test, $verifier)) {
                $source | Should -Not -Match 'MicrosoftWindowsPowerShellV2Root|Remove-PowerShellV2|Test-PowerShellV2|PowerShellV2Present|PowerShellV2Enabled'
            }
            (Join-Path $script:AdvancedRoot 'Private/Remove-PowerShellV2.ps1') | Should -Not -Exist
            (Join-Path $script:AdvancedRoot 'Private/Test-PowerShellV2.ps1') | Should -Not -Exist
            $restore | Should -Match 'function Restore-PowerShellV2'
            $restore | Should -Match "'PowerShellV2'\s*\{\s*return \[bool\]\(Restore-PowerShellV2"
        }

        It 'Should fail closed while detecting runtime target identities' {
            $source = Get-Content (Join-Path $script:AdvancedRoot 'Private/Get-AdvancedSecurityRuntimeApplicability.ps1') -Raw
            $source | Should -Match 'Get-Service -ErrorAction Stop'
            $source | Should -Match 'Get-NetAdapter -IncludeHidden -ErrorAction Stop'
            $source | Should -Match 'identity is ambiguous'

            $invoke = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $invoke | Should -Match 'Get-AdvancedSecurityRuntimeApplicability'
            $invoke | Should -Match 'runtime applicability changed during backup'
            $invoke | Should -Match 'SettingsRuntimeNotApplicable'
        }

        It 'Should make DryRun validate and report the frozen registry/firewall plan without changes' {
            $invoke = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $invoke | Should -Match 'Get-AdvancedSecurityDecisionAccounting'
            $invoke | Should -Match 'AdvancedSecurity DryRun registry target plan is empty or ambiguous'
            $invoke | Should -Match 'AdvancedSecurity firewall inventory drift'
            $invoke | Should -Match 'SettingsPreviewed\s*=\s*\[int\]\$decisionAccounting\.Attempted'
            $invoke | Should -Match 'ChangesMade\s*=\s*0'
        }

        It "Should skip managed Windows Update policy CSP values on unsupported editions" {
            $config = Get-Content (Join-Path $script:AdvancedRoot 'Config/WindowsUpdate.json') -Raw | ConvertFrom-Json
            [bool]$config.Settings.'1_OptionalUpdatesPolicy'.RequiresManagedPolicyEdition | Should -BeTrue
            [bool]$config.Settings.'3_DeliveryOptimization'.RequiresManagedPolicyEdition | Should -BeTrue
            [bool]$config.Settings.'2_ContinuousInnovationPreference'.RequiresManagedPolicyEdition | Should -BeFalse
            $apply = Get-Content (Join-Path $script:AdvancedRoot 'Private/Set-WindowsUpdate.ps1') -Raw
            $test = Get-Content (Join-Path $script:AdvancedRoot 'Private/Test-WindowsUpdate.ps1') -Raw
            $apply | Should -Match 'RequiresManagedPolicyEdition.*ManagedPoliciesSupported'
            $test | Should -Match 'NOT APPLICABLE on this edition'
        }

        It 'Should reconcile every AdvancedSecurity artifact before and after sealing, immediately before Apply' {
            $prestate = Get-Content (Join-Path $script:AdvancedRoot 'Private/Assert-AdvancedSecurityPrestate.ps1') -Raw
            $invoke = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $prestate | Should -Match 'Assert-AdvancedSecurityRegistrySnapshot'
            $prestate | Should -Match 'Get-AdvancedSecurityApplicability'
            $prestate | Should -Match 'Get-Service -ErrorAction Stop'
            $prestate | Should -Not -Match 'Get-WindowsOptionalFeature|MicrosoftWindowsPowerShellV2Root'
            $prestate | Should -Match 'Firewall policy changed after AdvancedSecurity backup'
            $prestate | Should -Match 'Wi-Fi Direct adapter inventory/state changed'
            $prestate | Should -Match 'NetBIOS adapter inventory/state changed'
            $prestate | Should -Match '\$currentInteractiveUsers = @\(\)[\s\S]{0,180}if \(\$null -ne \$currentInteractiveUser\)[\s\S]{0,180}\$currentInteractiveUsers = @\(\$currentInteractiveUser\)'
            ([regex]::Matches($invoke, 'Assert-AdvancedSecurityPrestate')).Count | Should -Be 2
            $firstGuard = $invoke.IndexOf('Assert-AdvancedSecurityPrestate')
            $seal = $invoke.IndexOf('Complete-ModuleBackup', $firstGuard)
            $secondGuard = $invoke.IndexOf('Assert-AdvancedSecurityPrestate', $seal)
            $apply = $invoke.IndexOf('# PHASE 2: APPLY', $secondGuard)
            $firstGuard | Should -BeLessThan $seal
            $seal | Should -BeLessThan $secondGuard
            $secondGuard | Should -BeLessThan $apply
        }
    }

    Context "Security Profiles" {
        It 'Should keep the Maximum-only discovery choice disabled in every shipped default config' {
            $rootConfig = Get-Content (Join-Path $repoRoot 'config.json') -Raw | ConvertFrom-Json
            [bool]$rootConfig.modules.AdvancedSecurity.disableDiscoveryProtocols | Should -BeFalse

            $configSource = Get-Content (Join-Path $repoRoot 'Core/Config.ps1') -Raw
            $configSource | Should -Match 'securityProfile\s*=\s*"Balanced"'
            $configSource | Should -Match 'disableDiscoveryProtocols\s*=\s*\$false'
        }

        It 'Should not let hidden GUI values override fixed Enterprise/Maximum RDP and UPnP semantics' {
            $invoke = Get-Content (Join-Path $script:AdvancedRoot 'Public/Invoke-AdvancedSecurity.ps1') -Raw
            $invoke | Should -Match '''Maximum''\s*\{\s*\$true\s*\}'
            $invoke | Should -Match '''Enterprise''\s*\{\s*\$false\s*\}'
            $invoke | Should -Match 'if \(\$SecurityProfile -eq ''Balanced''\)[\s\S]+Get-NonInteractiveValue -Module "AdvancedSecurity" -Key "disableUPnP"[\s\S]+else \{ \$true \}'
        }

        # DryRun smoke-tests: modules catch platform-incompat internally, so these
        # pass on both Windows + Linux pwsh (Should -Not -Throw is satisfied by
        # the graceful Success=false return path on non-Windows).

        It "Should accept Balanced profile" -Tag 'Interactive' {
            { Invoke-UnitNonInteractive { Invoke-AdvancedSecurity -SecurityProfile "Balanced" -DryRun -ErrorAction Stop } } | Should -Not -Throw
        }

        It "Should accept Enterprise profile" -Tag 'Interactive' {
            { Invoke-UnitNonInteractive { Invoke-AdvancedSecurity -SecurityProfile "Enterprise" -DryRun -ErrorAction Stop } } | Should -Not -Throw
        }

        It "Should accept Maximum profile" -Tag 'Interactive' {
            { Invoke-UnitNonInteractive { Invoke-AdvancedSecurity -SecurityProfile "Maximum" -DryRun -ErrorAction Stop } } | Should -Not -Throw
        }
    }

    Context "DryRun Behavior" {
        # Same rationale as "Security Profiles" above: platform incompatibility
        # is caught internally, so these run on Windows + Linux pwsh alike.

        It "Should accept DryRun parameter without errors" -Tag 'Interactive' {
            { Invoke-UnitNonInteractive { Invoke-AdvancedSecurity -DryRun -ErrorAction Stop } } | Should -Not -Throw
        }

        It "Should not modify system in DryRun mode" -Tag 'Interactive' {
            # The old assertion was `$? | Should -Be $true` after a helper whose
            # last statement is an assignment - it could never fail, and it read
            # no system state. If a regression stops threading -DryRun into the
            # workers, real registry values change during "preview". Fingerprint
            # every declared registry target before and after and require byte
            # equality; that is the no-mutation proof this test claims to be.
            function Get-DryRunRegistryFingerprint {
                $entries = [System.Collections.Generic.List[string]]::new()
                $targets = InModuleScope AdvancedSecurity { @(Get-AdvancedSecuritySchema5RegistryTargets) }
                foreach ($target in $targets) {
                    $path = [string]$target.Path
                    $name = [string]$target.Name
                    $line = "$path::$name="
                    if (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue) {
                        try {
                            $key = Get-Item -LiteralPath $path -ErrorAction Stop
                            if ($key.GetValueNames() -contains $name) {
                                $kind = $key.GetValueKind($name).ToString()
                                $value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                                $line += "$kind/" + (ConvertTo-Json -InputObject $value -Compress -Depth 5)
                            }
                            else { $line += '<absent-value>' }
                        }
                        catch { $line += "<unreadable:$($_.Exception.GetType().Name)>" }
                    }
                    else { $line += '<absent-key>' }
                    $entries.Add($line)
                }
                ($entries | Sort-Object) -join "`n"
            }

            $before = Get-DryRunRegistryFingerprint
            $result = Invoke-UnitNonInteractive { Invoke-AdvancedSecurity -DryRun -ErrorAction SilentlyContinue }
            $after = Get-DryRunRegistryFingerprint

            $after | Should -BeExactly $before -Because 'a DryRun preview must not change a single declared registry target'
            if ($result -and $result.PSObject.Properties['ChangesMade']) {
                [int]$result.ChangesMade | Should -Be 0
            }
        }
    }

    Context "Test-AdvancedSecurity Function" {

        BeforeAll {
            $script:ExplicitAdvancedSecurityIntent = @{
                SecurityProfile = 'Balanced'
                DisableRDP = $true
                AdminSharesDisabled = $true
                DisableUPnP = $true
                DisableWirelessDisplayCompletely = $false
                DisableDiscoveryProtocolsCompletely = $false
                DisableIPv6Completely = $false
                SkipFirewallLayer = $false
            }
        }

        It "rejects a standalone call whose intent was not supplied" {
            { Test-AdvancedSecurity -ErrorAction Stop } |
                Should -Throw '*requires an explicit current intent*'
        }

        It "Should return compliance results" -Skip:($PSVersionTable.PSEdition -ne 'Desktop' -and -not [bool]$IsWindows) {
            $result = Test-AdvancedSecurity @script:ExplicitAdvancedSecurityIntent -ErrorAction SilentlyContinue
            $result | Should -Not -BeNullOrEmpty
        }

        It "Compliance results should be an array of test results" -Skip:($PSVersionTable.PSEdition -ne 'Desktop' -and -not [bool]$IsWindows) {
            $result = Test-AdvancedSecurity @script:ExplicitAdvancedSecurityIntent -ErrorAction SilentlyContinue
            # Test-AdvancedSecurity returns an array of compliance results
            $result | Should -Not -BeNullOrEmpty
        }
    }
}

AfterAll {
    if ($null -eq $script:PreviousNonInteractiveEnvironment) {
        Remove-Item Env:NOIDPRIVACY_NONINTERACTIVE -ErrorAction SilentlyContinue
    }
    else {
        $env:NOIDPRIVACY_NONINTERACTIVE = $script:PreviousNonInteractiveEnvironment
    }
    # Cleanup
    Remove-Module AdvancedSecurity -ErrorAction SilentlyContinue
}
