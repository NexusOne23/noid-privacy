#Requires -Version 5.1

<#
.SYNOPSIS
    Framework-wide consistency tests across all 7 NoID Privacy modules.

.DESCRIPTION
    Cross-cutting structural tests that don't require admin/registry/network access.
    Catches drift between:
      - Module manifest declarations (.psd1) and the actual exported surface (.psm1).
      - Config JSONs (Privacy modes and module policy data) -- valid JSON + minimum
        schema shape.
      - Per-module setting counts vs Config/SettingsCounts.json (canonical source).
      - Module GUIDs are unique and non-Nil (Nil GUID only permitted in
        Modules/_ModuleTemplate/).

    These tests are intentionally side-effect-free so they run in unit-test mode
    and gate every PR via .github/workflows/pester-tests.yml.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: Pester 5.9.0, PowerShell 5.1
#>

BeforeDiscovery {
    $script:RepoRoot      = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ModulesRoot   = Join-Path $script:RepoRoot 'Modules'
    $script:CountsPath    = Join-Path $script:RepoRoot 'Config/SettingsCounts.json'

    $script:ProductionModules = @(
        'SecurityBaseline'
        'ASR'
        'DNS'
        'Privacy'
        'AntiAI'
        'EdgeHardening'
        'AdvancedSecurity'
    )
}

BeforeAll {
    $script:RepoRoot    = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ModulesRoot = Join-Path $script:RepoRoot 'Modules'
    $script:CountsPath  = Join-Path $script:RepoRoot 'Config/SettingsCounts.json'
    # BeforeDiscovery and BeforeAll execute in separate Pester phases/scopes.
    # Keep the runtime GUID-uniqueness inventory explicit instead of depending
    # on discovery state that Pester does not guarantee to preserve.
    $script:ProductionModules = @(
        'SecurityBaseline'
        'ASR'
        'DNS'
        'Privacy'
        'AntiAI'
        'EdgeHardening'
        'AdvancedSecurity'
    )
}

Describe 'Framework Manifest Consistency' {

    It 'Config/SettingsCounts.json exists and parses' {
        $script:CountsPath | Should -Exist
        { Get-Content $script:CountsPath -Raw -Encoding UTF8 | ConvertFrom-Json } | Should -Not -Throw
    }

    Context 'Per-module manifest (.psd1) integrity' -ForEach @(
        @{ Module = 'SecurityBaseline' }
        @{ Module = 'ASR' }
        @{ Module = 'DNS' }
        @{ Module = 'Privacy' }
        @{ Module = 'AntiAI' }
        @{ Module = 'EdgeHardening' }
        @{ Module = 'AdvancedSecurity' }
    ) {

        It "<Module> manifest parses with Test-ModuleManifest" {
            $manifestPath = Join-Path $script:ModulesRoot "$Module/$Module.psd1"
            $manifestPath | Should -Exist
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
            $manifest.Name | Should -Be $Module
        }

        It "<Module> declares a parseable, non-Nil GUID" {
            $manifestPath = Join-Path $script:ModulesRoot "$Module/$Module.psd1"
            $content = Get-Content $manifestPath -Raw -Encoding UTF8
            $content | Should -Match "GUID\s*=\s*['""]([0-9a-fA-F\-]{36})['""]"
            $guid = ($content | Select-String "GUID\s*=\s*['""]([0-9a-fA-F\-]{36})['""]").Matches[0].Groups[1].Value.ToLowerInvariant()
            $guid | Should -Not -Be '00000000-0000-0000-0000-000000000000'
        }

        It "<Module> ModuleVersion matches the canonical VERSION file" {
            $versionFile = Join-Path $script:RepoRoot 'VERSION'
            $expected = (Get-Content $versionFile -Raw).Trim()
            $manifest = Test-ModuleManifest -Path (Join-Path $script:ModulesRoot "$Module/$Module.psd1")
            $manifest.Version.ToString() | Should -Be $expected
        }

        It "<Module> FunctionsToExport is a fixed list (not '*')" {
            $manifest = Test-ModuleManifest -Path (Join-Path $script:ModulesRoot "$Module/$Module.psd1")
            $manifest.ExportedFunctions.Keys | Should -Not -Contain '*'
            @($manifest.ExportedFunctions.Keys).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Framework GUID Uniqueness' {
    It 'No two production manifests share the same GUID' {
        $guidMap = @{}
        foreach ($module in $script:ProductionModules) {
            $manifestPath = Join-Path $script:ModulesRoot "$module/$module.psd1"
            $content = Get-Content $manifestPath -Raw -Encoding UTF8
            $match = [regex]::Match($content, "GUID\s*=\s*['""]([0-9a-fA-F\-]{36})['""]")
            $match.Success | Should -BeTrue -Because "$module must declare a parseable GUID"
            $guid = $match.Groups[1].Value.ToLowerInvariant()
            $guidMap.ContainsKey($guid) | Should -BeFalse -Because "GUID '$guid' from $module collides with $($guidMap[$guid])"
            $guidMap[$guid] = $module
        }
    }
}

Describe 'Framework Settings-Count Canonical Source' {

    BeforeAll {
        $script:Counts = Get-Content $script:CountsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }

    It 'pins the published default-decision scope to the exact current total' {
        # Public documentation uses the reconciled exact count, not a marketing
        # floor. Any inventory change must deliberately update this assertion and
        # every mirrored product surface in the same review.
        [int]$script:Counts.framework.totalSettings | Should -Be 645
    }

    It 'binds the current release-note total to the canonical count' {
        $releaseNotes = Get-Content (Join-Path $script:RepoRoot 'Docs/RELEASE-NOTES-2.2.5.md') -Raw -Encoding UTF8
        $releaseNotes | Should -Match ([regex]::Escape(
                "Declared default-decision total is now $([int]$script:Counts.framework.totalSettings)"
            ))
    }

    It 'accepts only the closed GUI session identity option in addition to nonInteractive' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Config.ps1') -Raw -Encoding UTF8
        $source | Should -Match "'nonInteractive','sessionType','_comment'"
        $source | Should -Match "sessionType.*wizard.*advanced.*manual.*unknown"
    }

    It 'generates a default Privacy config that satisfies every current required decision' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Config.ps1') -Raw -Encoding UTF8
        $defaultSection = [regex]::Match(
            $source,
            'Privacy\s*=\s*@\{(?<body>[\s\S]*?)\n\s*\}\n\s*AntiAI'
        )
        $defaultSection.Success | Should -BeTrue
        $defaultSection.Groups['body'].Value | Should -Match 'applyStorePackagePolicy\s*=\s*\$false'
        $defaultSection.Groups['body'].Value | Should -Match 'removeBloatwareApps\s*=\s*"none"'
        $defaultSection.Groups['body'].Value | Should -Match 'removeWeatherWidget\s*=\s*\$false'
    }

    It 'Canonical total equals sum of per-module subtotals' {
        $total = [int]$script:Counts.framework.totalSettings
        $sum   = [int]$script:Counts.modules.SecurityBaseline.subtotal +
                 [int]$script:Counts.modules.ASR.rules +
                 [int]$script:Counts.modules.DNS.checks +
                 [int]$script:Counts.modules.Privacy.total +
                 [int]$script:Counts.modules.AntiAI.total +
                 [int]$script:Counts.modules.EdgeHardening.policies +
                 [int]$script:Counts.modules.AdvancedSecurity.settings
        $total | Should -Be $sum
    }

    It 'Keeps the product inventory stable while the selected Privacy scope follows the chosen mode' {
        $privacy = $script:Counts.modules.Privacy
        $nonPrivacy = [int]$script:Counts.modules.SecurityBaseline.subtotal +
            [int]$script:Counts.modules.ASR.rules +
            [int]$script:Counts.modules.DNS.checks +
            [int]$script:Counts.modules.AntiAI.total +
            [int]$script:Counts.modules.EdgeHardening.policies +
            [int]$script:Counts.modules.AdvancedSecurity.settings
        $productInventory = $nonPrivacy + [int]$privacy.modeTotals.Paranoid

        $productInventory | Should -Be 699
        ($nonPrivacy + [int]$privacy.modeTotals.MSRecommended) | Should -Be 645
        ($nonPrivacy + [int]$privacy.modeTotals.Strict) | Should -Be 670
        ($nonPrivacy + [int]$privacy.modeTotals.Paranoid) | Should -Be 699

        $verifier = Get-Content (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $verifier | Should -Match '\$EXPECTED_PRIVACY_PRODUCT_COUNT'
        $verifier | Should -Match 'ProductTargetInventory\s*=\s*\$productTargetInventory'
        $verifier | Should -Match 'Product Targets:'
        $verifier | Should -Match 'Verification Scope:'
    }

    It 'SecurityBaseline subtotal equals registry + securityTemplate + auditPolicies' {
        $sb  = $script:Counts.modules.SecurityBaseline
        $sum = [int]$sb.registry + [int]$sb.securityTemplate + [int]$sb.auditPolicies
        [int]$sb.subtotal | Should -Be $sum
    }

    It 'AdvancedSecurity feature count matches the Module 7 component list in Docs/FEATURES.md' {
        $featuresDoc = Get-Content (Join-Path $script:RepoRoot 'Docs/FEATURES.md') -Raw -Encoding UTF8
        $module7 = [regex]::Match($featuresDoc, '(?s)## [^\r\n]*Module 7: AdvancedSecurity.*?(?=\r?\n## [^#]|$)')
        $module7.Success | Should -BeTrue
        $componentHeaders = [regex]::Matches($module7.Value, '(?m)^#### \d+\. ')
        $componentHeaders.Count | Should -Be ([int]$script:Counts.modules.AdvancedSecurity.features)
    }

    It 'Privacy total equals registry plus Tier 1 declared policy targets; Tier 2 is informational-only' {
        $p = $script:Counts.modules.Privacy
        [int]$p.total | Should -Be ([int]$p.registry + [int]$p.tier1PolicyTargets)
        @($p.modeTotals.PSObject.Properties).Count | Should -Be 3
        ($p.modeTotals.PSObject.Properties.Name -join ',') | Should -Be 'MSRecommended,Strict,Paranoid'
        [int]$p.modeTotals.MSRecommended | Should -Be ([int]$p.total)
        [int]$p.modeTotals.Strict | Should -Be (61 + [int]$p.tier1PolicyTargets)
        [int]$p.modeTotals.Paranoid | Should -Be (90 + [int]$p.tier1PolicyTargets)
        $p.PSObject.Properties.Name | Should -Contain 'bloatwareBestEffortApps'
        [int]$p.bloatwareBestEffortApps | Should -BeGreaterThan 0
        # bloatwareBestEffortApps (Tier 2, best-effort, NOT exact BAVR) must never be
        # folded into the exact-BAVR total; only registry + tier1PolicyTargets may.
        ([int]$p.registry + [int]$p.tier1PolicyTargets + [int]$p.bloatwareBestEffortApps) | Should -Not -Be ([int]$p.total)

        $policy = Get-Content (Join-Path $script:ModulesRoot 'Privacy/Config/BloatwareRemovalPolicy.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $actualPolicyTargets = @($policy.PolicyTargets.PSObject.Properties | ForEach-Object { @($_.Value.PSObject.Properties) }).Count
        $actualPolicyTargets | Should -Be ([int]$p.tier1PolicyTargets)
        @($policy.PolicyTargets.PSObject.Properties).Count | Should -Be 26
        $tier1Root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages'
        $rootDefinition = $policy.PolicyTargets.PSObject.Properties[$tier1Root].Value
        @($rootDefinition.PSObject.Properties).Count | Should -Be 2
        $rootDefinition.Enabled.Type | Should -BeExactly 'DWord'
        $rootDefinition.Enabled.Value | Should -Be 1
        $rootDefinition.DynamicRemovalList.Type | Should -BeExactly 'MultiString'
        @($rootDefinition.DynamicRemovalList.Value).Count | Should -Be 0
        @($policy.PolicyTargets.PSObject.Properties.Name | Where-Object {
                $_ -match '\\Microsoft\.BingNews_8wekyb3d8bbwe$'
            }).Count | Should -Be 1
        @($policy.PolicyTargets.PSObject.Properties.Name | Where-Object {
                $_ -match '\\BingNews$|\\XboxGamingOverlay$'
            }).Count | Should -Be 0
        $bloatware = Get-Content (Join-Path $script:ModulesRoot 'Privacy/Config/Bloatware.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        (@($bloatware.RemoveApps).Count + @($bloatware.OptionalRemoveApps.PSObject.Properties).Count) | Should -Be ([int]$p.bloatwareBestEffortApps)
        [string]$bloatware.OptionalRemoveApps.WeatherWidget | Should -Be 'MicrosoftWindows.Client.WebExperience'
    }

    It 'AntiAI total equals registry policies plus real URI source checks' {
        $a = $script:Counts.modules.AntiAI
        [int]$a.total | Should -Be ([int]$a.policies + [int]$a.uriSourceChecks)
    }

    It 'Edge count excludes LGPO metadata and reconciles baseline plus privacy additions' {
        $edge = $script:Counts.modules.EdgeHardening
        [int]$edge.policies | Should -Be ([int]$edge.microsoftBaseline + [int]$edge.privacyAdditions)
        [int]$edge.policies | Should -Be 26
        [int]$edge.defaultSelected | Should -Be 25
        [int]$edge.strictSelected | Should -Be 26
        [int]$edge.metadataEntries | Should -Be 1
    }

    It 'AdvancedSecurity total equals deterministic firewall plus non-firewall checks' {
        $advanced = $script:Counts.modules.AdvancedSecurity
        [int]$advanced.settings | Should -Be ([int]$advanced.firewall + [int]$advanced.nonFirewall)
        [int]$advanced.firewall | Should -Be 17
    }
}

Describe 'Framework Config JSON Schema' {

    It 'DNS Providers.json declares cloudflare/quad9/adguard with ipv4+ipv6+doh' {
        $providersPath = Join-Path $script:ModulesRoot 'DNS/Config/Providers.json'
        $providersPath | Should -Exist
        $providers = (Get-Content $providersPath -Raw -Encoding UTF8 | ConvertFrom-Json).providers

        foreach ($key in @('cloudflare', 'quad9', 'adguard')) {
            $providers.PSObject.Properties.Name | Should -Contain $key
            $providers.$key.ipv4.primary | Should -Not -BeNullOrEmpty
            $providers.$key.ipv6.primary | Should -Not -BeNullOrEmpty
            $providers.$key.doh.template | Should -Not -BeNullOrEmpty
        }
        [string]$providers.cloudflare.intentToken | Should -BeExactly 'Cloudflare'
        [string]$providers.quad9.intentToken | Should -BeExactly 'Quad9'
        [string]$providers.adguard.intentToken | Should -BeExactly 'AdGuard'
    }

    It 'ASR Config/ASR-Rules.json has exactly 19 rules (canonical count)' {
        $rulesPath = Join-Path $script:ModulesRoot 'ASR/Config/ASR-Rules.json'
        $rulesPath | Should -Exist
        $rules = Get-Content $rulesPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $expected = [int]$script:Counts.modules.ASR.rules
        @($rules).Count | Should -Be $expected
    }

    It 'EdgeHardening Config/EdgePolicies.json is a non-empty flat array' {
        $edgePath = Join-Path $script:ModulesRoot 'EdgeHardening/Config/EdgePolicies.json'
        $edgePath | Should -Exist
        $policies = Get-Content $edgePath -Raw -Encoding UTF8 | ConvertFrom-Json
        @($policies).Count | Should -BeGreaterThan 0
        foreach ($entry in @($policies)) {
            $entry.KeyName   | Should -Not -BeNullOrEmpty
            $entry.ValueName | Should -Not -BeNullOrEmpty
            $entry.Type      | Should -Not -BeNullOrEmpty
        }
    }

    It 'Privacy mode configs (MSRecommended/Strict/Paranoid) all parse and declare Mode' {
        foreach ($mode in @('MSRecommended', 'Strict', 'Paranoid')) {
            $modePath = Join-Path $script:ModulesRoot "Privacy/Config/Privacy-$mode.json"
            $modePath | Should -Exist
            $cfg = Get-Content $modePath -Raw -Encoding UTF8 | ConvertFrom-Json
            $cfg.Mode | Should -Be $mode
        }
    }

    It 'Privacy bloatware removal states the exact-policy/non-exact-effect boundary for both tiers' {
        # The old single-tier implementation falsely labeled a winget reinstall as an
        # exact restore; those exact filenames must never return.
        (Join-Path $script:ModulesRoot 'Privacy/Private/Remove-Bloatware.ps1') | Should -Not -Exist
        (Join-Path $script:ModulesRoot 'Privacy/Public/Restore-Bloatware.ps1') | Should -Not -Exist
        (Join-Path $script:ModulesRoot 'Privacy/Private/Set-PolicyBasedAppRemoval.ps1') | Should -Not -Exist

        # Tier 1 (exact policy prestate, non-exact downstream deletion) and Tier 2
        # (classic best-effort) ship under distinct, honestly named files.
        foreach ($tier1File in @(
                'Privacy/Config/BloatwareRemovalPolicy.json'
            )) {
            (Join-Path $script:ModulesRoot $tier1File) | Should -Exist
        }
        foreach ($tier2File in @(
                'Privacy/Config/Bloatware.json', 'Privacy/Config/Bloatware-Map.json',
                'Privacy/Private/Remove-BloatwareApps.ps1', 'Privacy/Private/Get-PrivacyBloatwareConfig.ps1',
                'Privacy/Private/Get-PrivacyBloatwareActionLog.ps1', 'Privacy/Private/Assert-PrivacyBloatwareActionLog.ps1',
                'Privacy/Public/Restore-BloatwareApps.ps1'
            )) {
            (Join-Path $script:ModulesRoot $tier2File) | Should -Exist
        }

        $tier1 = Get-Content (Join-Path $script:ModulesRoot 'Privacy/Config/BloatwareRemovalPolicy.json') -Raw -Encoding UTF8
        $tier1 | Should -Match 'does not itself bring back an already-removed app'
        $tier2 = Get-Content (Join-Path $script:ModulesRoot 'Privacy/Config/Bloatware.json') -Raw -Encoding UTF8
        $tier2 | Should -Match 'NON-EXACT'

        $restoreSource = Get-Content (Join-Path $script:ModulesRoot 'Privacy/Public/Restore-BloatwareApps.ps1') -Raw -Encoding UTF8
        $restoreSource | Should -Match 'best-effort'
        $restoreSource | Should -Match 'NOT an exact restore'

        $rollbackSource = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $rollbackSource | Should -Match 'Privacy_BloatwareActions'
        $rollbackSource | Should -Match 'skipped by design'
    }

    It 'Privacy mode counts reconcile and no compatibility profile writes allow-valued relaxations' {
        function Get-PrivacyDefinitionCount {
            param([object]$Value)
            if ($null -eq $Value) { return 0 }
            if ($Value -is [PSCustomObject] -and
                $Value.PSObject.Properties['Type'] -and $Value.PSObject.Properties['Value']) {
                return 1
            }
            $count = 0
            if ($Value -is [PSCustomObject]) {
                foreach ($property in $Value.PSObject.Properties) {
                    $count += Get-PrivacyDefinitionCount -Value $property.Value
                }
            }
            return $count
        }

        $expectedModeRegistryCounts = @{ MSRecommended = 32; Strict = 55; Paranoid = 77 }
        foreach ($mode in $expectedModeRegistryCounts.Keys) {
            $modePath = Join-Path $script:ModulesRoot "Privacy/Config/Privacy-$mode.json"
            $config = Get-Content $modePath -Raw -Encoding UTF8 | ConvertFrom-Json
            $scope = [PSCustomObject]@{
                DataCollection = $config.DataCollection; Personalization = $config.Personalization
                SearchAndCloud = $config.SearchAndCloud; InputAndSync = $config.InputAndSync
                LocationAndAppPrivacy = $config.LocationAndAppPrivacy
            }
            (Get-PrivacyDefinitionCount -Value $scope) | Should -Be $expectedModeRegistryCounts[$mode]
        }

        $commonPath = Join-Path $script:ModulesRoot 'Privacy/Config/OneDrive.json'
        $commonSource = Get-Content $commonPath -Raw -Encoding UTF8
        $common = $commonSource | ConvertFrom-Json
        (Get-PrivacyDefinitionCount -Value $common.OneDrivePolicies) +
            (Get-PrivacyDefinitionCount -Value $common.StorePolicies) | Should -Be 4
        $commonSource | Should -Not -Match 'DisablePersonalSync'
        $commonSource | Should -Not -Match 'RemoveWindowsStore'

        foreach ($mode in @('MSRecommended', 'Strict')) {
            $source = Get-Content (Join-Path $script:ModulesRoot "Privacy/Config/Privacy-$mode.json") -Raw -Encoding UTF8
            $source | Should -Not -Match 'AllowClipboardHistory'
        }
        $ms = Get-Content (Join-Path $script:ModulesRoot 'Privacy/Config/Privacy-MSRecommended.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        @($ms.LocationAndAppPrivacy.PSObject.Properties).Count | Should -Be 0
        foreach ($mode in @('MSRecommended', 'Strict', 'Paranoid')) {
            $config = Get-Content (Join-Path $script:ModulesRoot "Privacy/Config/Privacy-$mode.json") -Raw -Encoding UTF8 | ConvertFrom-Json
            $machineCloud = $config.Personalization.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            $userCloud = $config.Personalization.'HKCU:\Software\Policies\Microsoft\Windows\CloudContent'
            (@($machineCloud.PSObject.Properties.Name) -join ',') |
                Should -Be 'DisableCloudOptimizedContent,DisableSoftLanding'
            foreach ($userPolicy in @(
                    'DisableTailoredExperiencesWithDiagnosticData', 'DisableWindowsSpotlightFeatures',
                    'DisableWindowsSpotlightOnSettings', 'DisableWindowsSpotlightOnActionCenter',
                    'DisableThirdPartySuggestions', 'DisableSpotlightCollectionOnDesktop'
                )) {
                @($userCloud.PSObject.Properties.Name) | Should -Contain $userPolicy
            }

            $explorer = $config.Personalization.'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            @($explorer.PSObject.Properties.Name) | Should -Contain 'Start_IrisRecommendations'
            @($explorer.PSObject.Properties.Name) | Should -Contain 'ShowSyncProviderNotifications'
            [int]$config.SearchAndCloud.'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'.BingSearchEnabled.Value | Should -Be 0
            [int]$config.SearchAndCloud.'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'.IsDynamicSearchBoxEnabled.Value | Should -Be 0
            [int]$config.SearchAndCloud.'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'.IsGlobalWebSearchProviderToggleEnabled.Value | Should -Be 0
            [int]$config.SearchAndCloud.'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings\WebSearchProviders'.'Microsoft.BingSearch_8wekyb3d8bbwe!App'.Value | Should -Be 0
        }
        foreach ($mode in @('Strict', 'Paranoid')) {
            $config = Get-Content (Join-Path $script:ModulesRoot "Privacy/Config/Privacy-$mode.json") -Raw -Encoding UTF8 | ConvertFrom-Json
            [int]$config.Personalization.'HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications'.EnableAccountNotifications.Value | Should -Be 0
            [int]$config.Personalization.'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'.Start_AccountNotifications.Value | Should -Be 0
            [int]$config.InputAndSync.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging'.AllowMessageSync.Value | Should -Be 0
        }
        foreach ($mode in @('MSRecommended', 'Strict')) {
            $config = Get-Content (Join-Path $script:ModulesRoot "Privacy/Config/Privacy-$mode.json") -Raw -Encoding UTF8 | ConvertFrom-Json
            @($config.SearchAndCloud.'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'.PSObject.Properties.Name) |
                Should -Not -Contain 'IsDeviceSearchHistoryEnabled' `
                -Because 'Microsoft documents device search history as local ranking data; usability-oriented profiles preserve that useful local-search state'
        }
        $paranoid = Get-Content (Join-Path $script:ModulesRoot 'Privacy/Config/Privacy-Paranoid.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        [int]$paranoid.SearchAndCloud.'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'.IsDeviceSearchHistoryEnabled.Value |
            Should -Be 0 -Because 'Paranoid deliberately accepts the local ranking-quality cost'
        [int]$paranoid.InputAndSync.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'.EnableFontProviders.Value | Should -Be 0
        [int]$paranoid.InputAndSync.'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'.PreventDeviceMetadataFromNetwork.Value | Should -Be 1

        $snapshotValidator = Get-Content (Join-Path $script:ModulesRoot 'Privacy/Private/Assert-PrivacyRegistrySnapshot.ps1') -Raw -Encoding UTF8
        $registryRestore = Get-Content (Join-Path $script:ModulesRoot 'Privacy/Private/Restore-PrivacyRegistryState.ps1') -Raw -Encoding UTF8
        foreach ($suffix in @(
                'Software\Microsoft\Windows\CurrentVersion\Search',
                'Software\Microsoft\Windows\CurrentVersion\SearchSettings',
                'Software\Microsoft\Windows\CurrentVersion\SearchSettings\WebSearchProviders',
                'Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications'
            )) {
            [regex]::Matches($snapshotValidator, [regex]::Escape("'$suffix'"), 'IgnoreCase').Count | Should -BeGreaterOrEqual 1
            [regex]::Matches($registryRestore, [regex]::Escape("'$suffix'"), 'IgnoreCase').Count | Should -BeGreaterOrEqual 1
        }
        foreach ($machinePath in @(
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging',
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'
            )) {
            [regex]::Matches($snapshotValidator, [regex]::Escape("'$machinePath'"), 'IgnoreCase').Count | Should -BeGreaterOrEqual 1
            [regex]::Matches($registryRestore, [regex]::Escape("'$machinePath'"), 'IgnoreCase').Count | Should -BeGreaterOrEqual 1
        }
    }

    It 'Privacy complete verification accounts for Cloud Clipboard preserve as NotChecked' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'disableCloudClipboardConfigured'
        $source | Should -Match "Name -eq 'AllowCrossDeviceClipboard'"
        $source | Should -Match 'Privacy\.PreserveCurrentState'
        $source | Should -Match '\$privacyNotChecked\.Count'
    }

    It 'post-Apply verification is scoped to the exact effective configuration' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $source | Should -Match '\[string\]\$ModulesCsv'
        $source | Should -Match '\[string\]\$ConfigPath'
        $source | Should -Match '\[string\]\$AppliedSessionPath'
        $source | Should -Match 'Requested verification scope does not match the enabled Apply configuration'
        $source | Should -Match 'Scoped post-Apply ASR verification requires the exact applied BAVR session path'
        $source | Should -Match 'Get-SealedAppliedAsrPlan'
        $source | Should -Match '\$sealedAppliedAsrPlan\.ActionMap'
        $source | Should -Match '\$bitLockerUsbChoiceIsAuthoritative'
        $source | Should -Match "ValueName -ceq 'RDVDenyWriteAccess'"
        $source | Should -Match '\$bitLockerUsbSettings\[0\]\.Data\s*=\s*if\s*\(\$configuredBitLockerUsbEnforcement\)' `
            -Because 'post-Apply verification must use the exact selected removable-drive policy instead of the static home default'
        $source | Should -Match "Test-VerificationModuleSelected 'AntiAI'"
        $antiAIContextBlock = [regex]::Match(
            $source,
            "if \(Test-VerificationModuleSelected 'AntiAI'\) \{[\s\S]+?Get-SecurityBaselineUserContext[\s\S]+?\r?\n\}",
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        $antiAIContextBlock.Success | Should -BeTrue `
            -Because 'only AntiAI may load the shared interactive-user helper; DNS-only and other scoped verification must remain independent'
        [regex]::Matches($source, 'Get-SecurityBaselineUserContext').Count | Should -Be 2 `
            -Because 'the helper name may appear only as the conditional helper filename and actual call'
        $source | Should -Match '\$frameworkConfigBase64'
        $source | Should -Match 'Standalone live-state verification does not consume an inherited in-memory Apply configuration'
        $source | Should -Match 'STABLE DENOMINATOR CONTRACT' `
            -Because 'applied-scope runs must publish the same declared totals as standalone runs'
        $source | Should -Not -Match 'Applied-scope category does not reconcile after filtering' `
            -Because 'the denominator subtraction was removed; deliberate placeholders are proven via notCheckedDeliberate'
        $source | Should -Match 'Get-StandaloneModuleIntent'
        $source | Should -Match '\$advancedSecurityIntent'
        $source | Should -Not -Match 'Get-SealedModulePrestate' `
            -Because 'standalone live verification must never derive choices from a deletable BAVR session'
        $source | Should -Match 'Privacy\.PreserveCurrentState'
        $source | Should -Match 'AdvancedSecurity\.RdpPreserved'
        $source | Should -Match 'Only declared values:' `
            -Because '**delvals. must allow values deliberately declared later for the same key'
        $source | Should -Match 'StartupType=\$actualStartType \(SCM\)' `
            -Because 'service startup verification must use effective SCM state when secedit omits it from export'
    }

    It 'Privacy complete verification uses the same edition applicability classifier as Apply' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'Get-PrivacyApplicability'
        $source | Should -Match 'Get-PrivacyTargetApplicability'
        $source | Should -Match '\$privacyNotApplicable'
    }

    It 'AntiAI Config/AntiAI-Settings.json declares Features object' {
        $aiPath = Join-Path $script:ModulesRoot 'AntiAI/Config/AntiAI-Settings.json'
        $aiPath | Should -Exist
        $settings = Get-Content $aiPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $settings.Features | Should -Not -BeNullOrEmpty
    }

    It 'AdvancedSecurity Config/SRP-Rules.json declares stable legacy .lnk path rules without runtime claims' {
        $srpPath = Join-Path $script:ModulesRoot 'AdvancedSecurity/Config/SRP-Rules.json'
        $srpPath | Should -Exist
        $srp = Get-Content $srpPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $srp.CVE        | Should -Be 'CVE-2025-9491'
        $srp.PathRules  | Should -Not -BeNullOrEmpty
        @($srp.PathRules).Count | Should -BeGreaterOrEqual 2
    }
}

Describe 'Framework Source-Encoding Hygiene (UTF-8 NO-BOM)' {

    It 'does not nest top-level JSON arrays under Windows PowerShell 5.1' {
        $powerShellSourceFiles = @(Get-ChildItem -LiteralPath $script:RepoRoot -File -Recurse |
            Where-Object { $_.Extension -in @('.ps1', '.psm1') })
        foreach ($powerShellSourceFile in $powerShellSourceFiles) {
            if ($powerShellSourceFile.FullName -like "$(Join-Path $script:RepoRoot '.git')*") { continue }
            $auditedPath = [string]$powerShellSourceFile.FullName
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $auditedPath,
                [ref]$tokens,
                [ref]$parseErrors
            )
            @($parseErrors).Count | Should -Be 0 -Because "$auditedPath must parse before its array expressions can be audited"
            $unsafeArrays = @($ast.FindAll({
                        param($node)
                        if ($node -isnot [System.Management.Automation.Language.ArrayExpressionAst]) { return $false }
                        $commandNames = @($node.SubExpression.FindAll({
                                    param($child)
                                    $child -is [System.Management.Automation.Language.CommandAst]
                                }, $true) | ForEach-Object { $_.GetCommandName() })
                        return 'Get-Content' -in $commandNames -and 'ConvertFrom-Json' -in $commandNames
                    }, $true))
            $unsafeArrays.Count | Should -Be 0 `
                -Because "wrapping ConvertFrom-Json in @() nests a top-level JSON array as one Object[] item on Windows PowerShell 5.1 ($auditedPath)"
        }
    }

    It 'does not count an optional module filter through a nullable array subexpression' {
        $rollbackSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $rollbackSource | Should -Not -Match '@\(\$RequestedModules\)\.Count' `
            -Because 'Windows PowerShell 5.1 StrictMode rejects the unfiltered full-restore null case'
        # The optional filter is materialized into a typed array before any
        # counting: the overlap guards receive [string[]]@($requestedModuleList),
        # whose .Count is StrictMode-safe even for the unfiltered (empty) case.
        $rollbackSource | Should -Match '-RequestedModules \(\[string\[\]\]@\(\$requestedModuleList\)\)'
    }

    It 'sorts stable registry fingerprint entries before hashing cross-process state' {
        $matrixSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11DecisionMatrix.ps1') -Raw -Encoding UTF8
        $matrixSource | Should -Match 'stableEntries\s*\|\s*Sort-Object Root, Path, Kind, Name, Type, Data' `
            -Because 'Windows registry-provider enumeration order is not stable across processes'
    }

    It 'keeps the decision-matrix configuration facade aligned with required decisions' {
        $matrixSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11DecisionMatrix.ps1') -Raw -Encoding UTF8
        $matrixSource | Should -Match 'Function:global:Get-NonInteractiveValue'
        $matrixSource | Should -Match '\[switch\]\$Required'
    }

    It 'includes native per-interface secure-DNS state in independent BAVR equality' {
        $matrixSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11DecisionMatrix.ps1') -Raw -Encoding UTF8
        $matrixSource | Should -Match 'DnsInterfaceDoh\.ps1'
        $matrixSource | Should -Match 'Get-DnsInterfaceDohState'
        $matrixSource | Should -Match 'DNS\s*=\s*Get-ObjectHash -InputObject @\(\$dnsState, \$dohState, \$dnsInterfaceState\)'
    }

    It 'includes every interactive-user Privacy registry surface in independent BAVR equality' {
        $matrixSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11DecisionMatrix.ps1') -Raw -Encoding UTF8
        foreach ($root in @(
                'Control Panel\International\User Profile',
                'SOFTWARE\Microsoft\InputPersonalization',
                'SOFTWARE\Microsoft\Personalization\Settings',
                'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager',
                'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
                'Software\Microsoft\Windows\CurrentVersion\Search',
                'Software\Microsoft\Windows\CurrentVersion\SearchSettings',
                'Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications',
                'Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement'
            )) {
            $matrixSource | Should -Match ([regex]::Escape("HKCU:\$root")) `
                -Because "$root is a mutable Privacy user surface and must survive exact restore"
        }
    }

    It 'excludes the OS-owned LSA boot latch consistently from stable restore equality' {
        $helperSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Windows11/Windows11StateFingerprint.ps1') -Raw -Encoding UTF8
        $helperSource | Should -Match "name -iin @\('LsaPid', 'RunAsPPLBoot'\)" `
            -Because 'RunAsPPLBoot is regenerated at boot from the restored authoritative RunAsPPL configuration'
    }

    It 'excludes only the proven root DHCP aggregate cache identities from Windows state equality' {
        . (Join-Path $script:RepoRoot 'Tests/Windows11/Windows11StateFingerprint.ps1')
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        foreach ($name in @('DhcpDomain', 'DhcpNameServer')) {
            (Test-Windows11OsOwnedVolatileRegistryEntry -Entry ([PSCustomObject]@{
                        Root = $root; Kind = 'Value'; Path = ''; Name = $name
                    })) | Should -BeTrue
        }
        foreach ($name in @('DhcpHostname', 'NameServer', 'Domain')) {
            (Test-Windows11OsOwnedVolatileRegistryEntry -Entry ([PSCustomObject]@{
                        Root = $root; Kind = 'Value'; Path = ''; Name = $name
                    })) | Should -BeFalse -Because "$name is not one of the observed OS aggregate cache identities"
        }
        (Test-Windows11OsOwnedVolatileRegistryEntry -Entry ([PSCustomObject]@{
                    Root = $root; Kind = 'Value'; Path = 'Interfaces\example'; Name = 'NameServer'
                })) | Should -BeFalse -Because 'a nearby persistent interface value must remain release-gated'
        (Test-Windows11OsOwnedVolatileRegistryEntry -Entry ([PSCustomObject]@{
                    Root = $root; Kind = 'Value'; Path = 'Interfaces\example'; Name = 'DhcpNameServer'
                })) | Should -BeTrue -Because 'the pre-existing adapter DHCP runtime normalization remains explicit'

        $matrixSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11DecisionMatrix.ps1') -Raw -Encoding UTF8
        $bavrSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11BavrValidation.ps1') -Raw -Encoding UTF8
        $matrixSource | Should -Match 'Test-Windows11OsOwnedVolatileRegistryEntry -Entry \$entry'
        $bavrSource | Should -Match 'Test-Windows11OsOwnedVolatileRegistryEntry -Entry \$Entry'
    }

    It 'fingerprints only declared stable AppX catalog identities' {
        $matrixSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11DecisionMatrix.ps1') -Raw -Encoding UTF8
        $matrixSource | Should -Match 'function Get-DeclaredAppxCatalogState'
        $matrixSource | Should -Match 'Modules\\Privacy\\Config\\Bloatware\.json'
        $matrixSource | Should -Match 'AppxCatalogTargets\s*=\s*Get-ObjectHash'
        $matrixSource | Should -Match 'PackageFamilyNames\s*=\s*\$familyNames'
        $matrixSource | Should -Match 'UserStates\s*=\s*\$userStates'
        $matrixSource | Should -Not -Match 'Sort-Object PackageFullName' `
            -Because 'Store version churn and unrelated Windows language packages are not NoID-owned configuration'
    }

    It "Files we emit ourselves are written without BOM (canonical PowerShell convention)" {
        # Spot-check a representative set of code+config files. UTF-8 BOM is allowed in JSON
        # we DO NOT generate ourselves (some IDEs add it on save) but our source files
        # should not carry it.
        $sourceFiles = @(
            Join-Path $script:RepoRoot 'NoIDPrivacy.ps1'
            Join-Path $script:RepoRoot 'install.ps1'
            Join-Path $script:RepoRoot 'Core/Framework.ps1'
            Join-Path $script:RepoRoot 'Core/Rollback.ps1'
            Join-Path $script:RepoRoot 'Config/SettingsCounts.json'
        )

        foreach ($path in $sourceFiles) {
            if (-not (Test-Path $path)) { continue }
            $bytes = [System.IO.File]::ReadAllBytes($path) | Select-Object -First 3
            $hasBom = ($bytes.Count -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
            $hasBom | Should -BeFalse -Because "$path must not start with a UTF-8 BOM"
        }
    }
}

Describe 'Core exact-restore safety invariants' {
    It 'Complete verification reconciles all four states and accepts only proven deliberate NotChecked targets' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $source | Should -Match '\$results\.Failed\s*=\s*\(\$results\.AllSettings\s*\|\s*Measure-Object'
        $source | Should -Match '\$results\.NotChecked\s*=\s*\(\$results\.AllSettings\s*\|\s*Measure-Object'
        $source | Should -Match '\$results\.NotApplicable\s*=\s*\(\$results\.AllSettings\s*\|\s*Measure-Object'
        $source | Should -Match '\$results\.Verified\s*\+\s*\$results\.Failed\s*\+\s*\$results\.NotChecked\s*\+\s*\$results\.NotApplicable'
        $source | Should -Match '\$unresolvedNotChecked\s*=\s*\[int\]\$results\.NotChecked\s*-\s*\[int\]\$results\.NotCheckedDeliberate'
        $source | Should -Match '\$verificationComplete\s*=\s*\(\$results\.Failed\s*-eq\s*0\s*-and\s*\$unresolvedNotChecked\s*-eq\s*0\)'
        $source | Should -Match '\$results\.VerificationComplete\s*=\s*\$verificationComplete'
        $source | Should -Match 'Get-VerificationNotCheckedAccounting'
        $source | Should -Match 'AffectedTargetCount'
        $source | Should -Match 'VerificationEvidenceSource'
        $source | Should -Match 'AdvancedSecurity\.WindowsUpdateUserOptIn'
        $source | Should -Not -Match '\$actual\s+-(?:c?eq|c?like|match).*Not checked:'
        $source | Should -Not -Match 'testDeliberatelyPreservedNotChecked'
        $source | Should -Match 'NOID_VERIFY_JSON='
        $source | Should -Match 'schemaVersion\s*=\s*3'
        $source | Should -Match 'intentReference\s*=\s*\[string\]\$standaloneIntentStatus'
        $source | Should -Match 'configSha256\s*=\s*\[string\]\$verificationConfigSha256'
        $source | Should -Match 'VERIFICATION INCOMPLETE:'
        $source | Should -Not -Match '\[\+\] VERIFICATION PASSED:'
        $source | Should -Not -Match 'Success Rate:'
        $source | Should -Not -Match 'return\s+\$verificationComplete'

        $bavrSource = Get-Content (Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11BavrValidation.ps1') -Raw -Encoding UTF8
        $bavrSource | Should -Match '\$accepted\s*=\s*\[int\]\$document\.Failed\s*-eq\s*0\s*-and\s*\[int\]\$document\.NotChecked\s*-eq\s*\[int\]\$document\.NotCheckedDeliberate'
        $bavrSource | Should -Match '\[bool\]\$contract\.complete\s*-ne\s*\$accepted'
        $bavrSource | Should -Not -Match '\$strictComplete\s*='

        $reportSource = Get-Content (Join-Path $script:RepoRoot 'Tools/Private/New-HardeningHtmlReport.ps1') -Raw -Encoding UTF8
        $reportSource | Should -Not -Match '\$reportStatus(?:Detail|Tone)?\s*='
        $reportSource | Should -Match 'required checks passed'
        $reportSource | Should -Match 'progress-bar-segment failed'
        $reportSource | Should -Match 'progress-bar-segment unproven'
        $reportSource | Should -Not -Match 'Evidence coverage:'
        $reportSource | Should -Not -Match 'Passed: all \$verifiableSettings verifiable checks'
    }

    It 'Complete verification uses the active Privacy mode count in progress and fail-closed results' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'function _GetPrivacyModeCount'
        $source | Should -Match '\$privacyExpectedForRun\s*=\s*_GetPrivacyModeCount -Mode \$privacyMode'
        $source | Should -Match 'Write-VerificationStep "Verifying Privacy - selected profile \$privacyMode \(\$privacyExpectedForRun targets\)\.\.\."'
        $source | Should -Not -Match 'Write-VerificationStep "Verifying Privacy Compliance \(\$EXPECTED_PRIVACY_COUNT\)'
        $source | Should -Match '\$results\.Failed\s*=\s*\$privacyFailedBefore \+ \$privacyExpectedForRun'
        $source | Should -Match 'Canonical Privacy mode count drift:'
        $source | Should -Match '-Name ''Privacy'' -Context \$privacyMode'
        $source | Should -Match 'Privacy module status disagrees with selected-profile presentation:'
        $source | Should -Match 'Write-VerificationModulePresentation -Presentation \$privacyModulePresentation'

        $reportSource = Get-Content (Join-Path $script:RepoRoot 'Tools/Private/New-HardeningHtmlReport.ps1') -Raw -Encoding UTF8
        $reportSource | Should -Not -Match '\$reportStatus(?:Detail|Tone)?\s*='
        $reportSource | Should -Match 'Privacy mode:'
        $reportSource | Should -Not -Match '<section class="privacy-verdict'
        $reportSource | Should -Not -Match '<details class="profile-comparison">'
        $reportSource | Should -Match '<table class="settings-table">'
        $reportSource | Should -Not -Match 'Apply intent reference'
        $reportSource | Should -Not -Match 'First mismatches'
    }

    It 'HTML reports render all four machine states and each structured NotChecked disposition' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Private/New-HardeningHtmlReport.ps1') -Raw -Encoding UTF8
        $source | Should -Match '\$computerName\s*=\s*if \(\$RedactComputerName\) \{ ''Redacted on request'' \} else \{ \[string\]\$env:COMPUTERNAME \}'
        $source | Should -Match '\$catNotCheckedLabel'
        $source | Should -Match "'BY CHOICE'"
        $source | Should -Match "'NO SAVED CHOICE'"
        $source | Should -Match "'CANNOT VERIFY'"
        $source | Should -Match "'Settings Not Checked'"
        $source | Should -Match '<span>Not applicable:</span>'
        $source | Should -Match 'foreach \(\$detail in \@\(\$category\.NotApplicableDetails\)\)'
        $source | Should -Match '<th>Path/Policy</th>'
        $source | Should -Match 'onclick="toggleModule\(''module-\$categoryName''\)"'
        $source | Should -Match "filterSettings\('notapplicable', this\)"
        $source | Should -Match '\[USER-SID\]'
        $source | Should -Match '\[EMAIL\]'
        $source | Should -Not -Match 'All \$totalSettings Settings Verified'
    }

    It 'keeps decoded registry paths as single-separator PowerShell paths in user-facing consumers' {
        $reportSource = Get-Content (Join-Path $script:RepoRoot 'Tools/Private/New-HardeningHtmlReport.ps1') -Raw -Encoding UTF8
        $privacySource = Get-Content (Join-Path $script:RepoRoot 'Modules/Privacy/Public/Invoke-PrivacyHardening.ps1') -Raw -Encoding UTF8

        $reportSource | Should -Not -Match 'Zones\\\\[0-4]' -Because 'ConvertFrom-Json has already decoded each JSON separator to one PowerShell backslash'
        $privacySource | Should -Not -Match 'Backups\\\\Session_' -Because 'PowerShell does not use backslash as a string escape character'
    }

    It 'decodes every module JSON registry path to one canonical separator' {
        function Get-RegistryPathCandidate {
            param([AllowNull()]$Value)

            if ($null -eq $Value) { return }
            if ($Value -is [string]) {
                if ($Value -match '^(?:HK(?:LM|CU|CR|U|CC):\\|Registry::HKEY_|HKEY_|\[(?:SOFTWARE|SYSTEM)\\)') {
                    Write-Output ([string]$Value)
                }
                return
            }
            if ($Value -is [System.Management.Automation.PSCustomObject]) {
                foreach ($property in $Value.PSObject.Properties) {
                    if ([string]$property.Name -match '^(?:HK(?:LM|CU|CR|U|CC):\\|Registry::HKEY_|HKEY_|\[(?:SOFTWARE|SYSTEM)\\)') {
                        Write-Output ([string]$property.Name)
                    }
                    Get-RegistryPathCandidate -Value $property.Value
                }
                return
            }
            if ($Value -is [System.Collections.IDictionary]) {
                foreach ($key in $Value.Keys) {
                    Get-RegistryPathCandidate -Value ([string]$key)
                    Get-RegistryPathCandidate -Value $Value[$key]
                }
                return
            }
            if ($Value -is [System.Collections.IEnumerable]) {
                foreach ($item in $Value) { Get-RegistryPathCandidate -Value $item }
            }
        }

        $candidates = [System.Collections.Generic.List[string]]::new()
        foreach ($jsonFile in Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'Modules') -Filter '*.json' -File -Recurse) {
            $document = Get-Content -LiteralPath $jsonFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($candidate in @(Get-RegistryPathCandidate -Value $document)) {
                $candidates.Add([string]$candidate)
            }
        }

        $candidates.Count | Should -BeGreaterThan 0
        foreach ($candidate in $candidates) {
            $candidate | Should -Not -Match '\\\\' -Because "decoded registry paths must not contain an empty path segment: $candidate"
            $candidate | Should -Not -Match '//' -Because "registry paths use the canonical Windows separator: $candidate"
            $candidate | Should -Not -Match '\\$' -Because "registry paths must not have a trailing separator: $candidate"
        }

        $baseline = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Modules/SecurityBaseline/ParsedSettings/Computer-RegistryPolicies.json') -Raw -Encoding UTF8 |
            ConvertFrom-Json
        @($baseline | Where-Object { $_.ValueName -in @('\\*\SYSVOL', '\\*\NETLOGON') }).Count | Should -Be 2
    }

    It 'complete verification honors the authoritative system-wide UAC choice' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $source | Should -Match '\$configuredUacMode -notin @\(''Strict'', ''SecureDesktop''\)'
        $source | Should -Match 'exact Apply configuration is missing SecurityBaseline\.standardUserElevationMode'
        $source | Should -Not -Match '\$configuredUacMode\s*=\s*''Strict'''
        $source | Should -Match 'elseif \(\$configuredUacMode -eq ''SecureDesktop''\) \{ ''4,1'' \}'
        $source | Should -Match 'else \{ ''4,0'' \}'
        $source | Should -Not -Match 'standardUserElevationMode must be Strict'
        $source | Should -Not -Match '\$interactiveEverydayAccountIsAdministrator'
    }

    It 'runs standalone verifier behavior evidence in the guarded Windows 11 release gate' {
        $workflow = Get-Content (Join-Path $script:RepoRoot '.github/workflows/windows11-bavr.yml') -Raw -Encoding UTF8
        $workflow | Should -Match 'Invoke-Windows11StandaloneVerifierValidation\.ps1'
        $workflow | Should -Match 'Windows11-Standalone-Verifier-Results\.json'
        $workflow | Should -Match 'Windows11-Standalone-Verifier-State/\*\*/\*\.json'
    }

    It 'has no configuration switch that can disable mandatory live backups' {
        $config = Get-Content (Join-Path $script:RepoRoot 'config.json') -Raw -Encoding UTF8
        $configCore = Get-Content (Join-Path $script:RepoRoot 'Core/Config.ps1') -Raw -Encoding UTF8
        $nonInteractive = Get-Content (Join-Path $script:RepoRoot 'Docs/NONINTERACTIVE-MODE.md') -Raw -Encoding UTF8

        $config | Should -Not -Match '"createBackup"'
        $configCore | Should -Not -Match 'createBackup'
        $nonInteractive | Should -Not -Match '"createBackup"'
    }

    It 'production and scaffold APIs expose no backup or verification bypass switches' {
        foreach ($relativePath in @(
                'Modules/SecurityBaseline/Public/Invoke-SecurityBaseline.ps1',
                'Modules/ASR/Public/Invoke-ASRRules.ps1',
                'Modules/AntiAI/Public/Invoke-AntiAI.ps1',
                'Modules/EdgeHardening/Public/Invoke-EdgeHardening.ps1',
                'Modules/AdvancedSecurity/Public/Invoke-AdvancedSecurity.ps1',
                'Modules/_ModuleTemplate/Public/Invoke-ModuleTemplate.ps1'
            )) {
            $source = Get-Content (Join-Path $script:RepoRoot $relativePath) -Raw -Encoding UTF8
            $source | Should -Not -Match 'SkipBackup|SkipVerify' -Because "$relativePath must make BAVR structurally mandatory"
        }
        (Get-Content (Join-Path $script:RepoRoot 'CONTRIBUTING.md') -Raw -Encoding UTF8) |
            Should -Not -Match 'may expose those copied parameters'
    }

    It 'has no dead global execution switches and initializes VERSION before first use' {
        $config = Get-Content (Join-Path $script:RepoRoot 'config.json') -Raw -Encoding UTF8
        $configCore = Get-Content (Join-Path $script:RepoRoot 'Core/Config.ps1') -Raw -Encoding UTF8
        $entryPoint = Get-Content (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $nonInteractive = Get-Content (Join-Path $script:RepoRoot 'Docs/NONINTERACTIVE-MODE.md') -Raw -Encoding UTF8

        foreach ($deadOption in @('autoReboot','autoConfirm')) {
            $config | Should -Not -Match ('"' + $deadOption + '"')
            $configCore | Should -Not -Match ('\b' + $deadOption + '\b')
            $nonInteractive | Should -Not -Match ('"' + $deadOption + '"\s*:')
        }
        $configCore | Should -Match '\$requiredOptions\s*=\s*@\(''nonInteractive''\)'
        $configCore | Should -Match 'unsupported configuration property'
        $configCore | Should -Match 'required and must be boolean'
        $entryPoint.IndexOf('$script:FrameworkVersion = (Get-Content') |
            Should -BeLessThan $entryPoint.IndexOf('Framework v$script:FrameworkVersion')
    }

    It 'keeps optional hardening decisions in executable contracts instead of dead JSON mirrors' {
        foreach ($relativePath in @(
                'Modules/AdvancedSecurity/Config/AdminShares.json',
                'Modules/AdvancedSecurity/Config/Firewall.json',
                'Modules/AdvancedSecurity/Config/RDP.json',
                'Modules/SecurityBaseline/Config/BitLockerPolicies.json'
            )) {
            (Join-Path $script:RepoRoot $relativePath) | Should -Not -Exist -Because `
                "$relativePath was an unused second source of truth that could silently drift from Apply, Verify and BAVR"
        }
    }

    It 'routes the mutually exclusive Modules parameter by binding state on Windows PowerShell 5.1' {
        $cli = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $cli | Should -Match '\$PSBoundParameters\.ContainsKey\(''Modules''\)'
        $cli | Should -Not -Match '@\(\$Modules\)\.Count' `
            -Because 'an unbound mandatory array from another parameter set can materialize as one null element in Windows PowerShell 5.1'
    }

    It 'rejects exact and case-variant duplicate Modules before framework initialization' {
        $entryPoint = Join-Path $script:RepoRoot 'NoIDPrivacy.ps1'
        { & $entryPoint -Modules @('ASR', 'ASR') } |
            Should -Throw '*Duplicate module names are not allowed: ASR*'
        { & $entryPoint -Modules @('ASR', 'asr') } |
            Should -Throw '*Duplicate module names are not allowed: asr*'

        $cli = Get-Content -LiteralPath $entryPoint -Raw -Encoding UTF8
        $guard = $cli.IndexOf("if (`$PSBoundParameters.ContainsKey('Modules'))")
        $initialization = $cli.IndexOf('# Enable strict mode for better error detection')
        $guard | Should -BeGreaterOrEqual 0
        $initialization | Should -BeGreaterThan $guard
    }

    It 'normalizes an empty All-module enumeration before the StrictMode Count gate' {
        $framework = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core/Framework.ps1') -Raw -Encoding UTF8
        $framework | Should -Match '\$modulesToExecute\s*=\s*@\(Get-EnabledModules\)' `
            -Because 'Get-EnabledModules emits no object when all modules are disabled, which otherwise assigns null and makes .Count fatal under StrictMode'
    }

    It 'does not load the unused legacy localization utility' {
        (Join-Path $script:RepoRoot 'Utils/Localization.ps1') | Should -Not -Exist
        (Get-Content (Join-Path $script:RepoRoot 'Core/Framework.ps1') -Raw) |
            Should -Not -Match 'Utils\\Localization\.ps1'
        (Get-Content (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw) |
            Should -Not -Match 'Utils\\Localization\.ps1'
    }

    It 'interactive startup never substitutes a no-op logger' {
        $source = Get-Content (Join-Path $script:RepoRoot 'NoIDPrivacy-Interactive.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'Required logger is missing'
        $source | Should -Match "Get-Command Write-Log -ErrorAction Stop"
        $source | Should -Not -Match 'function Write-Log\s*\{'
        $source | Should -Not -Match 'intentional no-op fallback'
    }

    It 'counts emitted warning log entries instead of relabeling curated module warning arrays' {
        $logger = Get-Content (Join-Path $script:RepoRoot 'Core/Logger.ps1') -Raw -Encoding UTF8
        $framework = Get-Content (Join-Path $script:RepoRoot 'Core/Framework.ps1') -Raw -Encoding UTF8

        $logger | Should -Match 'function Get-LogLevelCount'
        $logger | Should -Match '\$global:LoggerConfig\.LevelCounts\[\$levelName\]\s*=\s*\[int\]\$global:LoggerConfig\.LevelCounts\[\$levelName\]\s*\+\s*1'
        $framework | Should -Match '\$warningLogCountAtStart\s*=\s*Get-LogLevelCount -Level WARNING'
        $framework | Should -Match '\$updateWarningLogCount\s*=\s*\{'
        $framework | Should -Match '\$results\.WarningsLogged\s*=\s*\(Get-LogLevelCount -Level WARNING\) - \$warningLogCountAtStart'
        $framework | Should -Match 'Warnings: \$\(\$results\.WarningsLogged\)'
        $framework | Should -Not -Match 'Warnings: \$\(\$results\.Warnings\.Count\)'
        $entryPoint = Get-Content (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $entryPoint | Should -Match 'if \(\$result\.WarningsLogged -gt 0\)'
        $entryPoint | Should -Match 'Warnings: \$\(\$result\.WarningsLogged\)'
        $entryPoint | Should -Not -Match 'Warnings: \$\(\$result\.Warnings\.Count\)'
    }

    It 'contains no dead registry-key tracking or cached global mode state' {
        $rollback = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $entryPoint = Get-Content (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $nonInteractive = Get-Content (Join-Path $script:RepoRoot 'Core/NonInteractive.ps1') -Raw -Encoding UTF8
        ($rollback + $entryPoint) | Should -Not -Match 'NewlyCreatedKeys|Register-NewRegistryKey'
        $nonInteractive | Should -Not -Match '\$global:NonInteractiveMode'
        $nonInteractive | Should -Match '\$global:NoIDNonInteractiveBannerShown'
    }

    It 'never converts a missing non-empty SecurityBaseline privilege right into NotApplicable' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'Privilege Rights" -and \[string\]::IsNullOrEmpty\(\$expectedValue\)'
        $source | Should -Match 'Not found \(a non-empty declared target was not exported\)'
        $source | Should -Not -Match 'editionSpecificRights|domainOnlyDenyRights|Not applicable: privilege is unavailable'
    }

    It 'startup-only service backups never restore unowned runtime status' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $source | Should -Match '\[switch\]\$StartupOnly'
        $source | Should -Match 'RestoreRuntimeState = -not \[bool\]\$StartupOnly'
        $source | Should -Match 'if \(\$restoreRuntimeState\) \{'
        $source | Should -Match '\$restoreRuntimeState -and \$service\.Status\.ToString\(\) -ne \$desiredStatus'
    }

    It 'Edge baseline parser never overwrites runtime config or exports package SourceFile paths' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Parse-EdgeBaseline.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'MicrosoftBaselinePolicies\.json'
        $source | Should -Match 'MicrosoftBaselineProvenance\.json'
        $source | Should -Not -Match 'Join-Path \$OutputPath "EdgePolicies\.json"'
        $source | Should -Not -Match 'SourceFile\s*='
    }

    It 'Accepts 26H2 Experimental only with the explicit official DisplayVersion' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Validator.ps1') -Raw -Encoding UTF8
        $source | Should -Match '\$displayVersion -eq ''26H2''.*\$buildNumber -ge 26300'
        $source | Should -Match 'Build 26300-27999 is accepted only when Windows explicitly reports the official 26H2 DisplayVersion'
        $source | Should -Not -Match '26H2 Experimental build family inferred because DisplayVersion is unavailable'
    }

    It 'Registry restore never reports a protected-key skip as success' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $source | Should -Not -Match 'Smart JSON-Fallback'
        $source | Should -Match 'Registry restored and exact subtree verified'
    }

    It 'Malformed registry exports fail closed instead of implying key absence' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'schema-v2 sessions require a valid reg\.exe export or explicit EmptyMarker artifact'
    }

    It 'Scheduled-task backup uses schema 2 and verifies XML plus enabled state' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'SchemaVersion\s*=\s*2[\s\S]{0,240}CapturedState'
        $source | Should -Match 'Scheduled-task XML differs after restore'
        $source | Should -Match 'Scheduled-task enabled-state mismatch'
    }

    It 'Service backup and restore bind stable runtime, startup and delayed-start state' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'Service remained in transient state'
        $source | Should -Match 'Service backup schema/name does not match the sealed manifest target'
        $source | Should -Match 'Service post-restore mismatch'
        $source | Should -Match 'DelayedAutoStart value/type mismatch after restore'
    }

    It 'Binds embedded registry, service and task identities to manifest targets before restore' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'function Assert-ArtifactContentBinding'
        $source | Should -Match 'Registry artifact root does not match manifest target'
        $source | Should -Match 'Service artifact content does not match manifest target'
        $source | Should -Match 'Scheduled-task XML identity does not match manifest target'
        $source | Should -Match '-ExpectedTarget \(\[string\]\$serviceArtifact\.target\)'
    }

    It 'enumerates optional security-template sections without strict-mode property access' {
        $rollback = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $backup = Get-Content (Join-Path $script:RepoRoot 'Modules/SecurityBaseline/Private/Backup-SecurityTemplate.ps1') -Raw -Encoding UTF8
        foreach ($source in @($rollback, $backup)) {
            $source | Should -Match 'PSObject\.Properties\[\$sectionName\]'
            $source | Should -Not -Match '\$gpoProperty\.Value\.\$sectionName'
        }
    }

    It 'the destructive BAVR runner restores a sealed prestate even after Apply failure' {
        $runner = Get-Content (Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11BavrValidation.ps1') -Raw -Encoding UTF8
        $runner | Should -Match '\$cleanupRestoreAttempted\s*=\s*-not \$applySucceeded'
        $runner | Should -Match 'restorable -isnot \[bool\]'
        $runner | Should -Match '\$sealedModules\.Count -ne 1'
        $runner | Should -Match 'the sealed prestate cleanup restore succeeded'
        $runner | Should -Match 'SchemaVersion\s*=\s*3'
        $runner | Should -Match 'Invoke-IndependentStateFingerprint'
        $runner | Should -Match 'Compare-IndependentStateFingerprint'
        $runner | Should -Match 'Invoke-AppliedScopeVerification'
        $runner | Should -Match 'NOID_VERIFY_JSON='
        $runner | Should -Match 'Applied-scope HTML does not render the canonical'
        $runner | Should -Match '\$stateProcessOutput\s*=\s*@\(& \$windowsPowerShell @arguments 2>&1\)'
        $runner | Should -Match 'UnapprovedRawRegistryDifferences'
        $runner | Should -Match 'Sealed .* session is partial'
        $runner | Should -Match 'SessionFilesUnchanged'
        $runner | Should -Match 'New-ModuleScopedConfiguration'
        $runner | Should -Match 'EffectiveConfigurationSha256'
        $runner | Should -Match '\$moduleConfig\.enabled = \(\$declaredModule -ceq \$Module\)'
    }

    It 'the aggregate Pester runner cannot block on product prompts' {
        $runner = Get-Content (Join-Path $script:RepoRoot 'Tests/Run-AllTests.ps1') -Raw -Encoding UTF8
        $runner | Should -Match '\$env:NOIDPRIVACY_NONINTERACTIVE = ''true'''
        $runner | Should -Match "GetEnvironmentVariable\('NOIDPRIVACY_NONINTERACTIVE', 'Process'\)"
        $runner | Should -Match 'finally\s*\{[\s\S]*Remove-Item Env:NOIDPRIVACY_NONINTERACTIVE'
    }

    It 'Windows-only Pester skips use discovery-time platform state' {
        foreach ($relativePath in @('Tests/Unit/AdvancedSecurity.Tests.ps1', 'Tests/Unit/EdgeHardening.Tests.ps1')) {
            $source = Get-Content (Join-Path $script:RepoRoot $relativePath) -Raw -Encoding UTF8
            $source | Should -Not -Match '-Skip:\(-not \$script:RunningOnWindows\)'
            $source | Should -Match '-Skip:\(\$PSVersionTable\.PSEdition -ne ''Desktop'' -and -not \[bool\]\$IsWindows\)'
        }
    }

    It 'Validates Privacy schema and runtime applicability before any restore mutation' {
        $rollback = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $validator = Get-Content (Join-Path $script:RepoRoot 'Modules/Privacy/Private/Assert-PrivacyRegistrySnapshot.ps1') -Raw -Encoding UTF8
        $rollback | Should -Match 'Assert-PrivacyRegistrySnapshot -Snapshot \$json'
        $rollback | Should -Match 'Privacy service artifacts do not match the sealed applicability inventory'
        $rollback | Should -Match 'Privacy scheduled-task artifacts do not match the sealed applicability inventory'
        $validator | Should -Match 'Privacy schema-3 absent value must have null type and data'
        $validator | Should -Match 'Privacy registry snapshot target is outside the exact allowlist'
    }

    It 'Restores generic artifacts from the sealed inventory instead of filename globs' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'Assert-AllowedModuleArtifact'
        $source | Should -Match '\$registryArtifacts\s*=\s*@\(\$artifactInventory'
        $source | Should -Match '\$emptyMarkerArtifacts\s*=\s*@\(\$artifactInventory'
        $source | Should -Match '\$serviceArtifacts\s*=\s*@\(Get-ServiceArtifactsInRestoreOrder\s+-Artifacts\s+@\(\s*\$artifactInventory' `
            -Because 'sealed service artifacts must remain inventory-driven while being dependency-ordered before restore'
        $source | Should -Match '\$taskArtifacts\s*=\s*@\(\$artifactInventory'
        $source | Should -Not -Match 'Get-ChildItem[^\r\n]+\*_Registry\.reg'
        $source | Should -Not -Match 'Get-ChildItem[^\r\n]+\*_EMPTY\.json'
        $source | Should -Not -Match 'Get-ChildItem[^\r\n]+\*_Service\.json'
    }

    It 'Rejects unknown artifact identities and obsolete shared ASR state before restore' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'artifact without an explicit restore contract'
        $source | Should -Match 'Shared pre-framework artifacts are obsolete'
    }

    It 'the runners fail when a test file never executed instead of reporting zero failures' {
        # Prove the premise the gate rests on, with a real Pester run. A file that
        # cannot be PARSED never reaches discovery: its tests are never counted at
        # all, so FailedCount stays 0 while the whole file's coverage leaves the
        # suite. That is the blind spot - a bad merge or a deleted brace in any
        # *.Tests.ps1 file removes its coverage and the run still reports
        # "Failed: 0" and exits 0.
        $probeRoot = Join-Path ([IO.Path]::GetTempPath()) ("NoIDHarnessProbe-" + [Guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $probeRoot -Force
        try {
            Set-Content -LiteralPath (Join-Path $probeRoot 'Unparseable.Tests.ps1') -Encoding UTF8 -Value @'
Describe 'coverage that must not vanish quietly' {
    It 'asserts something important' { $true | Should -BeTrue
'@
            $probeConfig = New-PesterConfiguration
            $probeConfig.Run.Path = $probeRoot
            $probeConfig.Run.PassThru = $true
            $probeConfig.Output.Verbosity = 'None'
            $probe = Invoke-Pester -Configuration $probeConfig

            [int]$probe.FailedContainersCount | Should -BeGreaterThan 0 `
                -Because 'the file could not even be parsed'
            $probe.Result | Should -Not -BeExactly 'Passed'
            [int]$probe.FailedCount | Should -Be 0 `
                -Because 'this is the blind spot: nothing "failed", the tests simply never ran'
            [int]$probe.TotalCount | Should -Be 0 `
                -Because 'an unparseable file contributes no tests at all, so a count check on it alone cannot notice'
        }
        finally {
            Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }

        # Both runners and both CI gates must consult those counters, not FailedCount.
        foreach ($relativePath in @('Tests/Run-Tests.ps1', 'Tests/Run-AllTests.ps1', '.github/workflows/pester-tests.yml')) {
            $gate = Get-Content (Join-Path $script:RepoRoot $relativePath) -Raw -Encoding UTF8
            $gate | Should -Match 'FailedContainersCount' -Because "$relativePath must fail on a file that never ran"
            $gate | Should -Match 'FailedBlocksCount' -Because "$relativePath must fail on a block whose setup threw"
        }
    }

    It 'Refuses a partial restore that would strand a later module over a SecurityBaseline key' {
        # This used to be a Should -Match for the literal error string in
        # Rollback.ps1, which a comment satisfies as readily as a working guard -
        # and which said nothing about DNS, the overlap the guard actually missed.
        # SecurityBaseline creates HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
        # (EnableMulticast/EnableNetbios) and DNS then writes DoHPolicy into the same
        # key, so restoring the baseline alone left an unowned value behind and the
        # restore failed mid-run, after ASR had already been rolled back.
        . (Join-Path $script:RepoRoot 'Core/Rollback.ps1')

        # The guard's module set and the combined-prestate reconstruction's must be
        # the same set, or the guard permits a restore the engine cannot perform.
        $overlapModules = [string[]]@(Get-NoIDSecurityBaselineOverlapModule)
        $overlapModules | Should -Contain 'ASR'
        $overlapModules | Should -Contain 'DNS'

        foreach ($stranded in $overlapModules) {
            {
                Assert-NoIDSecurityBaselineOverlapRestore `
                    -SessionModuleNames @('SecurityBaseline', $stranded) `
                    -RequestedModules @('SecurityBaseline')
            } | Should -Throw -ExpectedMessage "*SecurityBaseline overlaps the later $stranded module*" `
                -Because "restoring SecurityBaseline alone strands the later $stranded module on a shared key"
        }

        # Restoring both together, restoring the whole session, restoring only the
        # later module, or a session that never applied the baseline are all allowed.
        {
            Assert-NoIDSecurityBaselineOverlapRestore `
                -SessionModuleNames @('SecurityBaseline', 'ASR', 'DNS') `
                -RequestedModules @('SecurityBaseline', 'ASR', 'DNS')
        } | Should -Not -Throw
        {
            Assert-NoIDSecurityBaselineOverlapRestore `
                -SessionModuleNames @('SecurityBaseline', 'ASR', 'DNS') `
                -RequestedModules @()
        } | Should -Not -Throw
        {
            Assert-NoIDSecurityBaselineOverlapRestore `
                -SessionModuleNames @('SecurityBaseline', 'DNS') `
                -RequestedModules @('DNS')
        } | Should -Not -Throw
        {
            Assert-NoIDSecurityBaselineOverlapRestore `
                -SessionModuleNames @('Privacy', 'DNS') `
                -RequestedModules @('DNS')
        } | Should -Not -Throw
    }

    It 'pins the fifteen SecurityBaseline-to-ASR target overlaps and their directions' {
        $baselinePolicies = Get-Content -LiteralPath (Join-Path $script:RepoRoot `
                'Modules/SecurityBaseline/ParsedSettings/Computer-RegistryPolicies.json') `
            -Raw -Encoding UTF8 | ConvertFrom-Json
        $asrRules = Get-Content -LiteralPath (Join-Path $script:RepoRoot `
                'Modules/ASR/Config/ASR-Rules.json') -Raw -Encoding UTF8 |
            ConvertFrom-Json
        $rulesKey = '[Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        $baselineAsr = @($baselinePolicies | Where-Object {
                ([string]$_.KeyName).Equals($rulesKey, [StringComparison]::OrdinalIgnoreCase)
            })
        $baselineIds = @($baselineAsr | ForEach-Object {
                ([Guid]([string]$_.ValueName)).ToString('D').ToLowerInvariant()
            })
        $moduleIds = @($asrRules | ForEach-Object {
                ([Guid]([string]$_.GUID)).ToString('D').ToLowerInvariant()
            })

        $baselineAsr.Count | Should -Be 15
        @($baselineIds | Sort-Object -Unique).Count | Should -Be 15
        @($baselineIds | Where-Object { $_ -notin $moduleIds }).Count | Should -Be 0
        @($baselineAsr | Where-Object {
                [string]$_.Type -cne 'REG_SZ' -or [string]$_.Data -notin @('1', '2')
            }).Count | Should -Be 0
        @($baselineAsr | Where-Object { [string]$_.Data -ceq '1' }).Count | Should -Be 14
        @($baselineAsr | Where-Object {
                [string]$_.ValueName -ieq 'd1e49aac-8f56-4280-b9ba-993a6d77406c' -and
                [string]$_.Data -ceq '2'
            }).Count | Should -Be 1
    }

    It 'Returns one Boolean restore result and propagates CLI restore failure as exit code 4' {
        $rollback = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $rollback | Should -Match 'function Restore-Session[\s\S]+\$booleanResults\[-1\]'
        $rollback | Should -Match 'function Restore-AllBackups[\s\S]+Restore-Session'
        $rollback | Should -Match '\$contractSessionPath\s*=\s*\[System\.IO\.Path\]::GetFullPath'
        ([regex]::Matches($rollback, 'sessionPath\s*=')).Count | Should -BeGreaterOrEqual 6 `
            -Because 'success and every machine-contract failure shape must bind the requested restore location'

        $cli = Get-Content (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $cli | Should -Match '\$success\s*=\s*Restore-Session'
        $cli | Should -Match 'if \(\$success\)[\s\S]{0,180}EXIT_SUCCESS[\s\S]{0,80}EXIT_ERROR_MODULE'
        $cli | Should -Match '\$script:EXIT_ERROR_MODULE\s*=\s*4'
    }

    It 'retains unsealed failed-module backups separately and uses no shared ASR restore bypass' {
        $rollback = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $framework = Get-Content (Join-Path $script:RepoRoot 'Core/Framework.ps1') -Raw -Encoding UTF8
        $rollback | Should -Match 'function Save-IncompleteModuleBackup'
        $rollback | Should -Match 'Refusing to detach a sealed module backup'
        $rollback | Should -Match 'IncompleteModuleBackup'
        $rollback | Should -Not -Match 'function Remove-OrphanedSharedArtifacts'
        $rollback | Should -Not -Match 'PreFramework_ASR'
        $framework | Should -Match 'Save-IncompleteModuleBackup -ModuleName \$moduleName'
        $framework | Should -Match "returned with a different unsealed backup active"
        $framework | Should -Match "returned no result with a different unsealed backup active"
        $framework | Should -Match "threw with a different unsealed backup active"
        [regex]::Matches(
            $framework,
            'Save-IncompleteModuleBackup\s+-ModuleName\s+\$activeBackupModule'
        ).Count | Should -BeGreaterOrEqual 2 `
            -Because 'both null-result and exception paths must detach the actual foreign backup identity rather than the requested module name'
        $framework | Should -Not -Match 'Register-SharedBackupFile|Backup-SharedRegistryKey'
    }

    It 'Treats skipped, aborted, missing and malformed module results as non-success' {
        $framework = Get-Content (Join-Path $script:RepoRoot 'Core/Framework.ps1') -Raw -Encoding UTF8
        $framework | Should -Match 'ModulesSkipped\s*=\s*0'
        $framework | Should -Match 'ModulesFailed\s*=\s*0'
        $framework | Should -Match "Status\s*=\s*'Aborted'"
        $framework | Should -Match "returned no result"
        $framework | Should -Match 'returned \$\(\$moduleResult.Count\) pipeline objects instead of exactly one result'
        $framework | Should -Match "foreach \(\`$errorPropertyName in @\('Error', 'ErrorMessage'\)\)"
        $framework | Should -Match 'if \(-not \$moduleErrorDetailAdded\)'
        $framework | Should -Match '\$applySucceeded\s*=\s*\(\$results\.Errors\.Count -eq 0'
        $framework | Should -Match '\$results\.Success\s*=\s*\$applySucceeded'
    }

    It 'Never offers or forces reboot after partial restore and only supplies concrete reasons' {
        $rollback = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $rollback | Should -Match 'Reboot prompt suppressed because restore did not complete successfully'
        $rollback | Should -Match 'Restore completed without a system-restart requirement'
        $rollback | Should -Not -Match 'PrivacyNonRestorableApps'
    }

    It 'Uses collision-resistant identifiers for every generated run artifact' {
        $logger = Get-Content (Join-Path $script:RepoRoot 'Core/Logger.ps1') -Raw -Encoding UTF8
        $rollback = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $asrBackup = Get-Content (Join-Path $script:RepoRoot 'Modules/ASR/Private/Backup-ASRRegistry.ps1') -Raw -Encoding UTF8
        $testRunner = Get-Content (Join-Path $script:RepoRoot 'Tests/Run-Tests.ps1') -Raw -Encoding UTF8

        $logger | Should -Match 'yyyyMMdd_HHmmss_fff'
        $logger | Should -Match '\[Guid\]::NewGuid\(\)[\s\S]*NoIDPrivacy_'
        $rollback | Should -Match 'Session_\$\{timestamp\}_\$sessionNonce'
        $rollback | Should -Match 'RESTORE_.*\$restoreNonce\.log'
        $rollback | Should -Match '\$Type`_\$\{timestamp\}_\$backupNonce'
        $asrBackup | Should -Match "-Name 'ASR_ActiveConfiguration'"
        $testRunner | Should -Match '\$resultId\s*=\s*"\$\{timestamp\}_\$resultNonce"'
    }

    It 'Derives apply reboot status only from successful structured module results' {
        $cli = Get-Content (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $interactive = Get-Content (Join-Path $script:RepoRoot 'NoIDPrivacy-Interactive.ps1') -Raw -Encoding UTF8
        $cli | Should -Match 'Invoke-Hardening returned \$\(\$result\.Count\) pipeline objects instead of exactly one structured result'
        $cli | Should -Match 'foreach \(\$moduleResult in @\(\$result\.ModuleResults\)\)'
        $cli | Should -Match "PSObject\.Properties\['RequiresReboot'\]"
        $cli | Should -Match "PSObject\.Properties\['RebootRequired'\]"
        $cli | Should -Not -Match '\$Module\s*-in\s*@\([^\)]*SecurityBaseline'
        $interactive | Should -Match 'if \(\$rebootRecommended\)\s*\{\s*Invoke-RebootPrompt'
        $interactive | Should -Not -Match '\$rebootRecommended\s*-or\s*\$allSucceeded'
    }

    It 'Runs every selected interactive module in one shared BAVR process' {
        $cli = Get-Content (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $interactive = Get-Content (Join-Path $script:RepoRoot 'NoIDPrivacy-Interactive.ps1') -Raw -Encoding UTF8
        $framework = Get-Content (Join-Path $script:RepoRoot 'Core/Framework.ps1') -Raw -Encoding UTF8

        $cli | Should -Match '\[string\[\]\]\$Modules'
        $cli | Should -Match 'Invoke-Hardening -Modules \$Modules'
        $interactive | Should -Match '& \$frameworkScript -Modules \$modulesToRun -VerboseLogging'
        $interactive | Should -Not -Match 'foreach \(\$mod in \$modulesToRun\)'
        $framework | Should -Match 'Initialize backup system ONCE before all modules'
    }

    It 'reconciles every production module prestate both before and after sealing' {
        $contracts = @(
            @{ Path = 'Modules/SecurityBaseline/Public/Invoke-SecurityBaseline.ps1'; Guard = 'Assert-SecurityBaselinePrestate'; ApplyMarker = 'Disable-XboxTask -DryRun:$DryRun' }
            @{ Path = 'Modules/ASR/Public/Invoke-ASRRules.ps1'; Guard = 'Assert-ASRPrestate'; ApplyMarker = '$applyResult = Set-ASRViaPowerShell' }
            @{ Path = 'Modules/DNS/Public/Invoke-DNSConfiguration.ps1'; Guard = 'Assert-DNSPrestate'; ApplyMarker = '# Get physical adapters' }
            @{ Path = 'Modules/Privacy/Public/Invoke-PrivacyHardening.ps1'; Guard = 'Assert-PrivacyPrestate'; ApplyMarker = '$registryWrites = Set-PrivacyRegistryTargets' }
            @{ Path = 'Modules/AntiAI/Public/Invoke-AntiAI.ps1'; Guard = 'Assert-AntiAIPrestate'; ApplyMarker = '$registryApply = Set-AntiAIRegistryTargets' }
            @{ Path = 'Modules/EdgeHardening/Public/Invoke-EdgeHardening.ps1'; Guard = 'Assert-EdgePrestate'; ApplyMarker = 'Set-EdgePolicies -AllowExtensions:$AllowExtensions -Snapshot $sealedSnapshot' }
            @{ Path = 'Modules/AdvancedSecurity/Public/Invoke-AdvancedSecurity.ps1'; Guard = 'Assert-AdvancedSecurityPrestate'; ApplyMarker = '# PHASE 2: APPLY' }
        )
        foreach ($contract in $contracts) {
            $source = Get-Content -LiteralPath (Join-Path $script:RepoRoot $contract.Path) -Raw -Encoding UTF8
            $guardMatches = [regex]::Matches($source, [regex]::Escape($contract.Guard))
            $sealIndex = $source.IndexOf('Complete-ModuleBackup')
            $firstGuardIndex = $source.IndexOf($contract.Guard)
            $secondGuardIndex = $source.IndexOf($contract.Guard, $firstGuardIndex + $contract.Guard.Length)
            $applyIndex = $source.IndexOf($contract.ApplyMarker, $secondGuardIndex)

            $guardMatches.Count | Should -Be 2 -Because "$($contract.Path) must have exactly two full prestate gates"
            $firstGuardIndex | Should -BeLessThan $sealIndex
            $secondGuardIndex | Should -BeGreaterThan $sealIndex
            $applyIndex | Should -BeGreaterThan $secondGuardIndex -Because "$($contract.Path) must not reach its first mutation before the sealed prestate passes again"
        }
    }

    It 'retains every direct-invocation module backup when an unsealed operation fails' {
        $contracts = @(
            @{ Path = 'Modules/SecurityBaseline/Public/Invoke-SecurityBaseline.ps1'; ModuleExpression = '\$moduleName' }
            @{ Path = 'Modules/ASR/Public/Invoke-ASRRules.ps1'; ModuleExpression = '\$moduleName' }
            @{ Path = 'Modules/DNS/Public/Invoke-DNSConfiguration.ps1'; ModuleExpression = '\$moduleName' }
            @{ Path = 'Modules/Privacy/Public/Invoke-PrivacyHardening.ps1'; ModuleExpression = '''Privacy''' }
            @{ Path = 'Modules/AntiAI/Public/Invoke-AntiAI.ps1'; ModuleExpression = '''AntiAI''' }
            @{ Path = 'Modules/EdgeHardening/Public/Invoke-EdgeHardening.ps1'; ModuleExpression = '''EdgeHardening''' }
            @{ Path = 'Modules/AdvancedSecurity/Public/Invoke-AdvancedSecurity.ps1'; ModuleExpression = '''AdvancedSecurity''' }
        )
        foreach ($contract in $contracts) {
            $source = Get-Content -LiteralPath (Join-Path $script:RepoRoot $contract.Path) -Raw -Encoding UTF8
            $source | Should -Match ("Save-IncompleteModuleBackup\s+-ModuleName\s+{0}" -f $contract.ModuleExpression) `
                -Because "$($contract.Path) must retain its own unsealed partial backup on failure"
        }
    }

    It 'uses decisive service and task inventories before reporting NotApplicable' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $source | Should -Match '\$allSecurityTemplateServices\s*=\s*@\(Get-Service -ErrorAction Stop\)'
        $source | Should -Match '\$allPrivacyServices\s*=\s*@\(Get-Service -ErrorAction Stop\)'
        $source | Should -Match '\$allPrivacyTasks\s*=\s*@\(Get-ScheduledTask -ErrorAction Stop\)'
        $source | Should -Match 'Privacy service inventory is ambiguous'
        $source | Should -Match 'Privacy scheduled-task inventory is ambiguous'

        foreach ($relativePath in @(
                'Modules/SecurityBaseline/Public/Invoke-SecurityBaseline.ps1',
                'Modules/AdvancedSecurity/Private/Backup-AdvancedSecuritySettings.ps1',
                'Modules/AdvancedSecurity/Private/Set-WirelessDisplaySecurity.ps1',
                'Modules/Privacy/Private/Disable-TelemetryServices.ps1'
            )) {
            $moduleSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot $relativePath) -Raw -Encoding UTF8
            $moduleSource | Should -Not -Match 'Get-Service\s+-Name[^\r\n]+-ErrorAction\s+SilentlyContinue' `
                -Because "$relativePath must not turn an unreadable SCM query into proven service absence"
        }
    }

    It 'rejects ambiguous owned identities instead of silently selecting a first match' {
        $criticalFiles = @(
            'Core/Rollback.ps1',
            'Modules/ASR/Private/Test-ConfigMgrPresence.ps1',
            'Modules/AdvancedSecurity/Private/Backup-AdvancedSecuritySettings.ps1',
            'Modules/AdvancedSecurity/Private/Set-DiscoveryProtocolsSecurity.ps1',
            'Modules/AdvancedSecurity/Private/Test-AdminShares.ps1',
            'Modules/AdvancedSecurity/Private/Test-RiskyServices.ps1',
            'Modules/AdvancedSecurity/Public/Restore-AdvancedSecuritySettings.ps1'
        )
        foreach ($relativePath in $criticalFiles) {
            $source = Get-Content -LiteralPath (Join-Path $script:RepoRoot $relativePath) -Raw -Encoding UTF8
            $source | Should -Not -Match '\|\s*Select-Object\s+-First\s+1' `
                -Because "$relativePath owns exact task, service, feature or adapter identities"
        }
        $rollback = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $rollback | Should -Match 'Scheduled-task identity is ambiguous'
        $rollback | Should -Not -Match 'PreFramework_ASR'
    }

    It 'fails Wireless Display Apply when any selected firewall rule helper returns false' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Modules/AdvancedSecurity/Private/Set-WirelessDisplaySecurity.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'if \(-not \(Set-AdvancedSecurityFirewallRuleDefinition -Definition \$rule\)\)'
        $source | Should -Match 'Miracast firewall rule application failed'
    }

    It 'does not create an unsolicited prerequisite connectivity request' {
        $validator = Get-Content (Join-Path $script:RepoRoot 'Core/Validator.ps1') -Raw -Encoding UTF8
        $validator | Should -Not -Match 'msftconnecttest|Test-InternetConnectivity'
        $validator | Should -Match 'InternetConnected\s*=\s*\$null'
    }

    It 'contains no system-restore-point code and never announces one' {
        # New-SystemRestorePoint had no caller in any product path; the sealed
        # BAVR backup is the restore mechanism. Neither the dead helper nor the
        # misleading "Creating restore point" console text may return.
        $rollback = Get-Content (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $rollback | Should -Not -Match 'function New-SystemRestorePoint'
        $rollback | Should -Not -Match 'Checkpoint-Computer -Description'

        $advancedSecurity = Get-Content (Join-Path $script:RepoRoot 'Modules/AdvancedSecurity/Public/Invoke-AdvancedSecurity.ps1') -Raw -Encoding UTF8
        $advancedSecurity | Should -Not -Match 'Creating restore point'
        $advancedSecurity | Should -Match 'Sealing backup prestate'
    }

    It 'requires PowerShell 5.1 consistently for every test entry and helper' {
        $testRoot = Join-Path $script:RepoRoot 'Tests'
        foreach ($testScript in Get-ChildItem -LiteralPath $testRoot -Filter '*.ps1' -File -Recurse) {
            $source = Get-Content -LiteralPath $testScript.FullName -Raw -Encoding UTF8
            $source | Should -Match '^#Requires -Version 5\.1' -Because "$($testScript.FullName) is part of the supported test surface"
        }
    }

    It 'keeps BOM-less PowerShell sources ASCII-safe for Windows PowerShell 5.1' {
        foreach ($scriptFile in Get-ChildItem -LiteralPath $script:RepoRoot -File -Recurse |
                Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1') }) {
            $bytes = [System.IO.File]::ReadAllBytes($scriptFile.FullName)
            @($bytes | Where-Object { $_ -gt 0x7F }).Count | Should -Be 0 -Because "$($scriptFile.FullName) has no BOM and must remain ASCII-safe on Windows PowerShell 5.1"
        }
    }

    It 'never mutates provider-opened read-only RegistryKey objects directly' {
        $moduleRoot = Join-Path $script:RepoRoot 'Modules'
        foreach ($scriptFile in Get-ChildItem -LiteralPath $moduleRoot -Filter '*.ps1' -File -Recurse) {
            $source = Get-Content -LiteralPath $scriptFile.FullName -Raw -Encoding UTF8
            $source | Should -Not -Match '\.(SetValue|DeleteValue)\(' `
                -Because "$($scriptFile.FullName) must use the writable registry provider and then read back type/data"
        }
    }

    It 'creates the HKU registry drive in process-global scope before returning HKU targets' {
        $moduleRoot = Join-Path $script:RepoRoot 'Modules'
        foreach ($scriptFile in Get-ChildItem -LiteralPath $moduleRoot -Filter '*.ps1' -File -Recurse) {
            $source = Get-Content -LiteralPath $scriptFile.FullName -Raw -Encoding UTF8
            foreach ($driveCreation in [regex]::Matches($source, '(?m)^.*New-PSDrive\s+-Name\s+HKU.*$')) {
                $driveCreation.Value | Should -Match '-Scope\s+Global' `
                    -Because "$($scriptFile.FullName) returns HKU paths that must remain valid after the helper returns"
            }
        }
    }

    It 'emits one closed GUI result contract backed by standardized module counts' {
        $main = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $config = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core/Config.ps1') -Raw -Encoding UTF8
        $framework = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core/Framework.ps1') -Raw -Encoding UTF8
        $dns = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Modules/DNS/Public/Invoke-DNSConfiguration.ps1') -Raw -Encoding UTF8
        $antiAi = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Modules/AntiAI/Public/Invoke-AntiAI.ps1') -Raw -Encoding UTF8

        $main | Should -Match 'NOID_RESULT_JSON='
        $main | Should -Match 'schemaVersion\s*=\s*2'
        $main | Should -Match 'configSha256\s*=\s*\[string\]\$script:ConfigPayloadSha256'
        $config | Should -Match '\$script:ConfigPayloadSha256'
        $main | Should -Match 'totalSettingsApplied\s*=\s*\[int\]\$result\.TotalSettingsApplied'
        $framework | Should -Match 'AppliedSettingsCount'
        $framework | Should -Match 'TotalSettingsApplied \+= \$appliedSettingsCount'
        $framework | Should -Match 'elseif \(\$success\)\s*\{\s*\$moduleResult \| Add-Member -NotePropertyName Status -NotePropertyValue \$\(if \(\$DryRun\) \{ ''DryRun'' \} else \{ ''Success'' \}\) -Force' `
            -Because 'every successful module status must be normalized to the closed GUI contract even when a module exposes an internal status such as Applied'
        $dns | Should -Match 'ChecksApplied\s*=\s*if \(\$DryRun\) \{ 0 \} else \{ \$dnsCheckCount \}'
        $antiAi | Should -Match 'UriSourceChecksApplied\s*=\s*\[int\]\$uriApply\.Verified'
    }

    It 'never promotes an extension blocklist under explicit allow intent' {
        $source = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'allow-extensions intent requires no block-all entry'
        $source | Should -Match 'unexpected blocklist entry'
        $source | Should -Not -Match 'preserved external state'
    }
}
