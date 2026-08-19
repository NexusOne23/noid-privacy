#Requires -Version 5.1

<#
.SYNOPSIS
    Unit tests for the SecurityBaseline module.

.DESCRIPTION
    Pester v5 structural tests covering manifest integrity, exported function
    surface, parsed-settings JSON validity, and parameter contracts for the
    SecurityBaseline module. Behavioral tests that mutate the host live in the
    Integration suite (Tests/Integration/SecurityBaseline.Integration.Tests.ps1)
    and are -Skip'd by default in CI to keep unit runs side-effect-free.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: Pester 5.9.0
#>

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ModuleRoot = Join-Path $script:RepoRoot "Modules/SecurityBaseline"
    $script:ModulePath = Join-Path $script:ModuleRoot "SecurityBaseline.psm1"
    $script:ManifestPath = Join-Path $script:ModuleRoot "SecurityBaseline.psd1"
    $script:ParsedPath = Join-Path $script:ModuleRoot "ParsedSettings"

    if (Test-Path $script:ModulePath) {
        Import-Module $script:ModulePath -Force -ErrorAction Stop
    }
    else {
        throw "Module not found: $script:ModulePath"
    }

    # Dot-source Core + Utils so module-internal calls (Write-Log etc.) resolve
    foreach ($file in @("Logger.ps1", "Config.ps1", "Validator.ps1", "Rollback.ps1")) {
        $p = Join-Path (Join-Path $script:RepoRoot "Core") $file
        if (Test-Path $p) { . $p }
    }
    foreach ($file in @("Compatibility.ps1")) {
        $p = Join-Path (Join-Path $script:RepoRoot "Utils") $file
        if (Test-Path $p) { . $p }
    }

    if (Get-Command Initialize-Logger -ErrorAction SilentlyContinue) {
        Initialize-Logger -EnableConsole $false
    }

    # Also expose the pure interactive choice reader to this test scope so its
    # input behavior can be verified without invoking live Windows mutations.
    . (Join-Path $script:ModuleRoot 'Private/Read-StandardUserElevationModeChoice.ps1')
}

Describe "SecurityBaseline manifest" {
    It "manifest file exists" {
        $script:ManifestPath | Should -Exist
    }

    It "manifest parses with Test-ModuleManifest" {
        $manifest = Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop
        $manifest | Should -Not -BeNullOrEmpty
        $manifest.Name | Should -Be "SecurityBaseline"
    }

    It "manifest version is non-empty and SemVer-shaped" {
        $manifest = Test-ModuleManifest -Path $script:ManifestPath
        $manifest.Version | Should -Not -BeNullOrEmpty
        $manifest.Version.ToString() | Should -Match '^\d+\.\d+\.\d+$'
    }

    It "manifest declares LicenseUri + ProjectUri" {
        $manifest = Test-ModuleManifest -Path $script:ManifestPath
        $manifest.LicenseUri | Should -Not -BeNullOrEmpty
        $manifest.ProjectUri | Should -Not -BeNullOrEmpty
    }
}

Describe 'Logger severity accounting' {
    It 'counts every accepted WARNING entry independently of curated module result arrays' {
        $before = Get-LogLevelCount -Level WARNING

        Write-Log -Level WARNING -Message 'Logger counter probe one' -Module 'Test'
        Write-Log -Level WARNING -Message 'Logger counter probe two' -Module 'Test'

        (Get-LogLevelCount -Level WARNING) - $before | Should -Be 2
    }
}

Describe "SecurityBaseline exported surface" {
    It "exports Invoke-SecurityBaseline" {
        Get-Command Invoke-SecurityBaseline -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }

    It "exports Restore-SecurityBaseline" {
        Get-Command Restore-SecurityBaseline -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }

    It "Invoke-SecurityBaseline supports DryRun switch" {
        $cmd = Get-Command Invoke-SecurityBaseline
        $cmd.Parameters.ContainsKey('DryRun') | Should -BeTrue
        $cmd.Parameters['DryRun'].ParameterType | Should -Be ([System.Management.Automation.SwitchParameter])
    }
}

Describe "SecurityBaseline ParsedSettings JSON" {
    It "Summary.json exists and parses" {
        $p = Join-Path $script:ParsedPath "Summary.json"
        $p | Should -Exist
        { Get-Content $p -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
    }

    It "AuditPolicies.json exists, parses, and every entry has a SubcategoryGUID" {
        $p = Join-Path $script:ParsedPath "AuditPolicies.json"
        $p | Should -Exist
        $data = Get-Content $p -Raw | ConvertFrom-Json
        $data.Count | Should -BeGreaterThan 0
        # Locale-independent audit verification relies on SubcategoryGUID being present
        foreach ($entry in $data) {
            $entry.SubcategoryGUID | Should -Not -BeNullOrEmpty -Because "every audit-policy entry needs a GUID for language-independent matching"
        }
    }

    It "Computer-RegistryPolicies.json exists and parses" {
        $p = Join-Path $script:ParsedPath "Computer-RegistryPolicies.json"
        $p | Should -Exist
        { Get-Content $p -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
    }

    It "User-RegistryPolicies.json exists and parses" {
        $p = Join-Path $script:ParsedPath "User-RegistryPolicies.json"
        $p | Should -Exist
        { Get-Content $p -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
    }

    It "SecurityTemplates.json exists and parses" {
        $p = Join-Path $script:ParsedPath "SecurityTemplates.json"
        $p | Should -Exist
        { Get-Content $p -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
    }
}

Describe "SecurityBaseline strict-mode safety" {
    It "initializes every decision field consumed by intent and release-matrix contracts" {
        $src = Get-Content (Join-Path $script:ModuleRoot "Public/Invoke-SecurityBaseline.ps1") -Raw
        foreach ($property in @(
                'BitLockerUSBEnforcement',
                'SubmitAllSamples',
                'SmartScreenWarnMode',
                'StandardUserElevationMode',
                'ConsentPromptBehaviorUser',
                'InteractiveAccountIsAdministrator'
            )) {
            $src | Should -Match ([regex]::Escape($property) + '\s*=\s*\$null')
        }
    }

    It "admits supported 24H2 and 25H2 clients through one profile and BAVR path" {
        $src = Get-Content (Join-Path $script:ModuleRoot "Public/Invoke-SecurityBaseline.ps1") -Raw
        $src | Should -Match "Release -notin @\('24H2', '25H2', '26H2'\)"
        $src | Should -Match '\$is24H2 = \(\$displayVersion -eq ''24H2'''
        $src | Should -Match '-not \$is24H2 -and -not \$is25H2'
        $src | Should -Not -Match 'ParsedSettings\\24H2|ParsedSettings/24H2'
    }

    It "Write-ModuleLog fallback does not call Write-Log when Write-Log is absent" {
        # Inspect Invoke-SecurityBaseline source: the fallback default-branch should not
        # invoke Write-Log (would recurse to a missing command). Earlier audit found this bug.
        $src = Get-Content (Join-Path $script:ModuleRoot "Public/Invoke-SecurityBaseline.ps1") -Raw
        # Match the local Write-ModuleLog function body
        $localFn = [regex]::Match($src, 'function\s+Write-ModuleLog[\s\S]*?^\s{8}\}', [System.Text.RegularExpressions.RegexOptions]::Multiline)
        $localFn.Success | Should -BeTrue
        $localFn.Value | Should -Not -Match 'default\s*\{\s*Write-Log'
    }

    It "Restore-SecurityBaseline delegates only to the canonical sealed-session engine" {
        $src = Get-Content (Join-Path $script:ModuleRoot "Public/Restore-SecurityBaseline.ps1") -Raw
        $src | Should -Match 'Restore-Session -SessionPath'
        $src | Should -Match 'Assert-SessionManifest'
        $src | Should -Not -Match 'secedit\.exe|auditpol\.exe|Restore-FromBackup'
    }
}

Describe "SecurityBaseline exact user and registry BAVR" {
    It "binds user policies to the interactive Explorer owner instead of elevated HKCU" {
        (Join-Path $script:ModuleRoot 'Private/Get-SecurityBaselineUserContext.ps1') | Should -Exist
        $invoke = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-SecurityBaseline.ps1') -Raw
        $backup = Get-Content (Join-Path $script:ModuleRoot 'Private/Backup-RegistryPolicies.ps1') -Raw
        $apply = Get-Content (Join-Path $script:ModuleRoot 'Private/Set-RegistryPolicies.ps1') -Raw
        $invoke | Should -Match '\$userContext\s*=\s*Get-SecurityBaselineUserContext'
        $invoke | Should -Match '\$userRegistryRoot\s*=\s*\$userContext\.Root'
        $invoke | Should -Match '-UserRegistryRoot \$userRegistryRoot'
        $backup | Should -Match 'SchemaVersion\s*=\s*4'
        $backup | Should -Match 'UserRegistryRoot\s*=\s*\$UserRegistryRoot'
        $backup | Should -Match 'AbsentAncestorKeys'
        $backup | Should -Match 'OriginalValueName'
        $apply | Should -Match '\$fullPath\s*=\s*"\$UserRegistryRoot\\\$keyPath"'
        $apply | Should -Not -Match '\$fullPath\s*=\s*"HKCU:'
    }

    It "restores clear-key values and exact key hierarchy from current and legacy sealed schemas" {
        $restore = Get-Content (Join-Path $script:ModuleRoot 'Private/Restore-RegistryPolicies.ps1') -Raw
        $restore | Should -Match 'Unsupported RegistryPolicies backup schema'
        $restore | Should -Match '\$schemaVersion\s+-notin\s+@\(3, 4\)'
        $restore | Should -Match 'AbsentAncestorKeys'
        $restore | Should -Match 'value-name casing mismatch'
        $restore | Should -Match 'A \*\*delvals\. directive owns the complete value set'
        $restore | Should -Match 'Originally absent SecurityBaseline key contains unowned (subkey|values)'
        $restore | Should -Match 'Registry key-existence mismatch'
        $restore | Should -Match 'Mount-UserRegistryHiveForRestore -Sid \$Matches\[1\]'
        $restore | Should -Match 'Dismount-UserRegistryHiveAfterRestore -Mount \$mount'
    }

    It "keeps standard-user UAC choice constrained to explicit system-wide strict 0 or secure-desktop 1" {
        $invoke = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-SecurityBaseline.ps1') -Raw
        $context = Get-Content (Join-Path $script:ModuleRoot 'Private/Get-SecurityBaselineUserContext.ps1') -Raw
        $invoke | Should -Match 'if \(\$StandardUserElevationMode -eq ''SecureDesktop''\) \{ 1 \} else \{ 0 \}'
        $invoke | Should -Match 'system-wide standard-user policy does not change an administrator account''s'
        $invoke | Should -Not -Match 'SecureDesktop is invalid for this account layout'
        $invoke | Should -Not -Match '\$interactiveAccountIsAdministrator -and \$StandardUserElevationMode -ne ''Strict'''
        $invoke | Should -Match 'Read-StandardUserElevationModeChoice[\s\S]*?-InteractiveAccountIsAdministrator:\$interactiveAccountIsAdministrator'
        $invoke | Should -Not -Match 'elseif \(\$interactiveAccountIsAdministrator\)'
        $invoke | Should -Match 'if \(\$enableBitLockerUSBEnforcement\)[\s\S]*?else \{\s*Write-ModuleLog -Level DEBUG -Message "User selected: BitLocker USB enforcement DISABLED'
        $invoke | Should -Not -Match '\.DeleteValue\(|\.SetValue\('
        $context | Should -Match 'TokenContainsGroupSid\(\[int\]\$_, ''S-1-5-32-544''\)'
        $context | Should -Match 'GetTokenInformation\(tokenHandle, 2, tokenGroups'
        $context | Should -Match 'EqualSid\(entry\.Sid, targetSid\)'
        $context | Should -Match 'IsAdministrator\s*=\s*\[bool\]\$administratorMembership\[0\]'
        $context | Should -Match 'New-PSDrive[^\r\n]+-Scope Global'
        $invoke | Should -Not -Match 'ConsentPromptBehaviorUser\s*=\s*3'
    }

    It "offers the same Y/N standard-user UAC decision to administrator and standard-user sessions" -TestCases @(
        @{ IsAdministrator = $true;  Answer = '';  Expected = 'Strict' }
        @{ IsAdministrator = $true;  Answer = 'n'; Expected = 'Strict' }
        @{ IsAdministrator = $true;  Answer = 'y'; Expected = 'SecureDesktop' }
        @{ IsAdministrator = $false; Answer = 'N'; Expected = 'Strict' }
        @{ IsAdministrator = $false; Answer = 'Y'; Expected = 'SecureDesktop' }
    ) {
        param($IsAdministrator, $Answer, $Expected)

        $script:uacAnswers = [System.Collections.Generic.Queue[string]]::new()
        $script:uacAnswers.Enqueue([string]$Answer)
        $script:uacReadCount = 0
        $actual = Read-StandardUserElevationModeChoice `
            -InteractiveAccountIsAdministrator:$IsAdministrator `
            -ReadChoice {
                $script:uacReadCount++
                $script:uacAnswers.Dequeue()
            } 6>$null

        $actual | Should -BeExactly $Expected
        $script:uacReadCount | Should -Be 1
    }

    It "retries invalid standard-user UAC input and exposes only the Y/N contract" {
        $script:uacAnswers = [System.Collections.Generic.Queue[string]]::new()
        $script:uacAnswers.Enqueue('K')
        $script:uacAnswers.Enqueue('Y')
        $script:uacReadCount = 0

        $actual = Read-StandardUserElevationModeChoice `
            -InteractiveAccountIsAdministrator:$true `
            -ReadChoice {
                $script:uacReadCount++
                $script:uacAnswers.Dequeue()
            } 6>$null

        $choiceSource = Get-Content (Join-Path $script:ModuleRoot 'Private/Read-StandardUserElevationModeChoice.ps1') -Raw
        $actual | Should -BeExactly 'SecureDesktop'
        $script:uacReadCount | Should -Be 2
        $choiceSource | Should -Match 'Your choice \[Y/N\] \(default: N\)'
        $choiceSource | Should -Match '\[N\] NO - Keep Strict \(Microsoft Baseline, Recommended\)'
        $choiceSource | Should -Match '\[Y\] YES - Use secure-desktop administrator credential prompt'
        $choiceSource | Should -Not -Match '\[S/K\]|\[K\]|S or K'
    }

    It "keeps the Pro release gate aligned with the machine-wide profile decisions" {
        $releaseGate = Get-Content (Join-Path $script:RepoRoot 'Docs/WINDOWS-VM-RELEASE-GATE.md') -Raw

        $releaseGate | Should -Match 'must not silently\s+override the selected machine-wide decision'
        $releaseGate | Should -Match 'Quick & Secure and Balanced\s+apply SecureDesktop `1`'
        $releaseGate | Should -Match 'High Security applies Strict `0`'
        $releaseGate | Should -Not -Match 'must be forced to strict `0` regardless'
    }

    It "previews the configured non-interactive UAC decision during DryRun" {
        $invoke = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-SecurityBaseline.ps1') -Raw
        $sectionStart = $invoke.IndexOf('# Step 2.4: Standard-user elevation behavior.', [StringComparison]::Ordinal)
        $sectionEnd = $invoke.IndexOf('$consentPromptBehaviorUser = if', $sectionStart, [StringComparison]::Ordinal)
        $sectionStart | Should -BeGreaterOrEqual 0
        $sectionEnd | Should -BeGreaterThan $sectionStart
        $section = $invoke.Substring($sectionStart, $sectionEnd - $sectionStart)

        $nonInteractiveIndex = $section.IndexOf('if ($isNonInteractive)', [StringComparison]::Ordinal)
        $dryRunIndex = $section.IndexOf('elseif ($DryRun)', [StringComparison]::Ordinal)
        $nonInteractiveIndex | Should -BeGreaterOrEqual 0
        $dryRunIndex | Should -BeGreaterThan $nonInteractiveIndex
        $section | Should -Match "Get-NonInteractiveValue[\s\S]{0,180}-Module 'SecurityBaseline'[\s\S]{0,180}-Key 'standardUserElevationMode'[\s\S]{0,120}-Required"
    }

    It "previews the configured non-interactive BitLocker USB decision during DryRun" {
        $invoke = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-SecurityBaseline.ps1') -Raw
        $sectionStart = $invoke.IndexOf('# Step 2.3: BitLocker USB Drive Protection', [StringComparison]::Ordinal)
        $sectionEnd = $invoke.IndexOf('# Step 2.4: Standard-user elevation behavior.', $sectionStart, [StringComparison]::Ordinal)
        $sectionStart | Should -BeGreaterOrEqual 0
        $sectionEnd | Should -BeGreaterThan $sectionStart
        $section = $invoke.Substring($sectionStart, $sectionEnd - $sectionStart)

        $nonInteractiveIndex = $section.IndexOf('if ($isNonInteractive)', [StringComparison]::Ordinal)
        $dryRunIndex = $section.IndexOf('elseif ($DryRun)', [StringComparison]::Ordinal)
        $nonInteractiveIndex | Should -BeGreaterOrEqual 0
        $dryRunIndex | Should -BeGreaterThan $nonInteractiveIndex
        $section | Should -Match "Get-NonInteractiveValue[\s\S]{0,180}-Key 'bitLockerUSBEnforcement'[\s\S]{0,120}-Required"
        $section | Should -Match '\$result\.Details\.BitLockerUSBEnforcement\s*=\s*\[bool\]\$enableBitLockerUSBEnforcement'
    }

    It "uses target-counted exact registry prestates for security-template and UAC deviations" {
        $templateBackup = Get-Content (Join-Path $script:ModuleRoot 'Private/Backup-SecurityTemplateRegistryState.ps1') -Raw
        $templateRestore = Get-Content (Join-Path $script:ModuleRoot 'Private/Restore-SecurityTemplateRegistryState.ps1') -Raw
        $uacBackup = Get-Content (Join-Path $script:ModuleRoot 'Private/Backup-UACStandardUserElevation.ps1') -Raw
        $uacRestore = Get-Content (Join-Path $script:ModuleRoot 'Private/Restore-UACStandardUserElevation.ps1') -Raw
        $templateBackup | Should -Match 'SchemaVersion\s*=\s*3'
        $templateBackup | Should -Match 'TargetCount\s*=\s*\$states.Count'
        $templateBackup | Should -Match 'AbsentAncestorKeys'
        $templateBackup | Should -Match 'OriginalName'
        $templateRestore | Should -Match '\$schemaVersion\s+-notin\s+@\(2, 3\)'
        $templateRestore | Should -Match 'value-name casing verification failed'
        $templateRestore | Should -Match 'Security-template key-existence verification failed'
        $templateRestore | Should -Not -Match '\.DeleteValue\(|\.SetValue\('
        $uacBackup | Should -Match 'SchemaVersion\s*=\s*3'
        $uacBackup | Should -Match 'AbsentAncestorKeys'
        $uacBackup | Should -Match 'OriginalName'
        $uacBackup | Should -Match 'roundTrip\.KeyExisted -isnot \[bool\]'
        $uacRestore | Should -Match 'UAC key-existence verification failed'
        $uacRestore | Should -Match '\$schemaVersion\s+-notin\s+@\(2, 3\)'
        $uacRestore | Should -Match 'UAC value-name casing verification failed'
        $uacRestore | Should -Match 'backup\.KeyExisted -isnot \[bool\]'
        $uacRestore | Should -Match 'UAC value/type verification failed'
        $uacRestore | Should -Not -Match '\.DeleteValue\(|\.SetValue\('
    }

    It "captures and restores the complete value set owned by delvals directives" {
        $backup = Get-Content (Join-Path $script:ModuleRoot 'Private/Backup-RegistryPolicies.ps1') -Raw
        $apply = Get-Content (Join-Path $script:ModuleRoot 'Private/Set-RegistryPolicies.ps1') -Raw
        $restore = Get-Content (Join-Path $script:ModuleRoot 'Private/Restore-RegistryPolicies.ps1') -Raw
        $backup | Should -Match 'ComputerClearKeys'
        $backup | Should -Match 'foreach \(\$valueName in \$key\.GetValueNames\(\)\)'
        $apply | Should -Match '\*\*delvals\. verification failed'
        $apply | Should -Match 'Remove-ItemProperty -LiteralPath \$fullPath'
        $apply | Should -Not -Match '\.DeleteValue\('
        $restore | Should -Match 'A \*\*delvals\. directive owns the complete value set'
        $restore | Should -Match 'Registry clear-key value-set mismatch'
        $restore | Should -Match 'contains unowned subkey'
        $restore | Should -Match 'contains state after managed values were restored'
        $restore | Should -Match 'Remove-Item -LiteralPath \$path -Force -ErrorAction Stop'
        $restore | Should -Not -Match 'Remove-Item -LiteralPath \$path -Recurse'
        $restore | Should -Not -Match '\.DeleteValue\(|\.SetValue\('
    }

    It "captures every absent parent key created by a forced registry path" {
        $helperPath = Join-Path $script:ModuleRoot 'Private/Get-RegistryHierarchyPrestate.ps1'
        $helperPath | Should -Exist
        $helper = Get-Content -LiteralPath $helperPath -Raw
        $helper | Should -Match 'function Get-RegistryHierarchyPrestate'
        $helper | Should -Match 'while \(\$cursor\.Length -gt \$normalizedBoundary\.Length\)'
        $helper | Should -Match 'Test-Path -LiteralPath \$cursor -PathType Container -ErrorAction Stop'
        $helper | Should -Match 'function Get-ExactRegistryValueName'
    }

    It "validates all audit identities and service-template inputs before mutation" {
        $audit = Get-Content (Join-Path $script:ModuleRoot 'Private/Set-AuditPolicies.ps1') -Raw
        $template = Get-Content (Join-Path $script:ModuleRoot 'Private/Set-SecurityTemplate.ps1') -Raw
        $audit | Should -Match 'HashSet\[Guid\]'
        $audit | Should -Match 'invalid or duplicate subcategory'
        $template | Should -Match '\$installedServices\s*=\s*@\(Get-Service -ErrorAction Stop\)'
        $template | Should -Match 'Conflicting duplicate security-template setting'
        $template | Should -Match 'service inventory differs from sealed prestate'
        $template | Should -Match "section -eq 'Privilege Rights'[\s\S]*IsNullOrWhiteSpace"
        $invoke = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-SecurityBaseline.ps1') -Raw
        $invoke | Should -Match 'Backup-ServiceConfiguration -ServiceName \$serviceName -StartupOnly'
        $invoke | Should -Match 'Assert-SecurityBaselineServicePrestate'
        (Join-Path $script:ModuleRoot 'Private/Assert-SecurityBaselineServicePrestate.ps1') | Should -Exist
    }

    It "backs up and verifies owned audit GUIDs natively and restores them with auditpol" {
        $backup = Get-Content (Join-Path $script:ModuleRoot 'Private/Backup-AuditPolicies.ps1') -Raw
        $restore = Get-Content (Join-Path $script:ModuleRoot 'Private/Restore-AuditPolicies.ps1') -Raw
        $native = Get-Content (Join-Path $script:ModuleRoot 'Private/Get-AuditPolicyState.ps1') -Raw
        $invoke = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-SecurityBaseline.ps1') -Raw
        $backup | Should -Match 'SchemaVersion\s*=\s*2'
        $backup | Should -Match 'Get-AuditPolicyState -SubcategoryGuid'
        $backup | Should -Not -Match 'auditpol\.exe|/backup'
        $restore | Should -Match "Start-Process -FilePath 'auditpol\.exe'"
        $restore | Should -Match '"/subcategory:\{\$\(\$policy\.Guid\.ToString\(''D''\)\)\}"'
        $restore | Should -Match 'Get-AuditPolicyState -SubcategoryGuid \$policy\.Guid'
        $restore | Should -Not -Match 'AuditSetSystemPolicy|/restore'
        $native | Should -Not -Match 'AuditSetSystemPolicy'
        $native | Should -Match 'private static extern void AuditFree\(IntPtr buffer\)'
        $native | Should -Not -Match 'if \(!AuditFree\(buffer\)\)' `
            -Because 'Microsoft declares AuditFree as VOID with no return value'
        $native | Should -Match 'policy\.AuditingInformation == 0 \? 4U' `
            -Because 'query flag 0 means the effective no-auditing state, while set flag 0 means unchanged'
        $invoke | Should -Match 'AuditPolicies\.json'
    }

    It "filters security-template rollback to owned non-registry sections" {
        $backup = Get-Content (Join-Path $script:ModuleRoot 'Private/Backup-SecurityTemplate.ps1') -Raw
        $restore = Get-Content (Join-Path $script:ModuleRoot 'Private/Restore-SecurityTemplate.ps1') -Raw
        $apply = Get-Content (Join-Path $script:ModuleRoot 'Private/Set-SecurityTemplate.ps1') -Raw
        $backup | Should -Match 'filtered owned security-template backup'
        $backup | Should -Match 'foreach \(\$sectionName in @\(''System Access'', ''Privilege Rights''\)\)'
        $restore | Should -Match 'foreach \(\$section in @\(''System Access'', ''Privilege Rights''\)\)'
        $apply | Should -Match "Service General Setting'[\s\S]*\(\[0-9\]\+\)"
        $apply | Should -Match 'Verify the effective SCM state directly instead'
        $apply | Should -Match 'Get-Service -Name \(\[string\]\$name\) -ErrorAction Stop'
    }

    It 'reconciles all six artifact classes and services on both sides of manifest sealing' {
        $guard = Get-Content (Join-Path $script:ModuleRoot 'Private/Assert-SecurityBaselinePrestate.ps1') -Raw
        $invoke = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-SecurityBaseline.ps1') -Raw
        foreach ($evidence in @(
                'RegistryPolicies', 'SecurityTemplateRegistryState',
                'UACStandardUserElevation', 'AuditPolicies',
                'SecurityTemplate', 'XboxTask'
            )) {
            $guard | Should -Match ([regex]::Escape($evidence))
        }
        $guard | Should -Match 'Assert-SecurityBaselineServicePrestate'
        $guard | Should -Match 'clear-key value inventory changed'
        $guard | Should -Match 'Get-AuditPolicyState -SubcategoryGuid'
        $guard | Should -Match 'System Access/Privilege Rights changed after backup'
        ([regex]::Matches($invoke, 'Assert-SecurityBaselinePrestate')).Count | Should -Be 2
        $firstGuard = $invoke.IndexOf('Assert-SecurityBaselinePrestate')
        $seal = $invoke.IndexOf('Complete-ModuleBackup', $firstGuard)
        $secondGuard = $invoke.IndexOf('Assert-SecurityBaselinePrestate', $seal)
        $apply = $invoke.IndexOf('# Step 4: Disable Xbox Task', $secondGuard)
        $firstGuard | Should -BeLessThan $seal
        $seal | Should -BeLessThan $secondGuard
        $secondGuard | Should -BeLessThan $apply
    }
}


Describe 'SecurityBaseline DryRun accounting' {
    It 'previews the full planned security-template count instead of zero' {
        # Regression pin: the DryRun branch of Set-SecurityTemplate once
        # returned SettingsApplied = 0 while its sibling helpers keep the
        # module convention "Applied carries the planned count in a preview".
        # Invoke-SecurityBaseline end{} folds that sum into SettingsPreviewed
        # and reconciles it against the canonical declared total, so a zero
        # here failed every DryRun with "accounting mismatch: 358 vs 425".
        if (-not (Test-Path function:global:Write-Log)) {
            Set-Item -Path function:global:Write-Log -Value { param($Level, $Message, $Module, $Exception) $null = $Level, $Message, $Module, $Exception }
        }
        $declared = [int](Get-Content (Join-Path $script:RepoRoot 'Config/SettingsCounts.json') -Raw |
                ConvertFrom-Json).modules.SecurityBaseline.securityTemplate
        $declared | Should -BeGreaterThan 0

        Mock -ModuleName SecurityBaseline Get-Service {
            foreach ($serviceName in @('XboxGipSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc')) {
                [PSCustomObject]@{ Name = $serviceName }
            }
        }
        $templatePath = Join-Path $script:ParsedPath 'SecurityTemplates.json'
        $result = InModuleScope SecurityBaseline -Parameters @{ TemplatePath = $templatePath } {
            param($TemplatePath)
            Set-SecurityTemplate `
                -SecurityTemplatePath $TemplatePath `
                -ServiceNamesWithSealedPrestate @('XboxGipSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc') `
                -DryRun
        }
        $result.Success | Should -BeTrue
        [int]$result.SettingsNotApplicable | Should -Be 0
        [int]$result.SettingsApplied | Should -Be $declared
        [int]$result.SectionsApplied | Should -BeGreaterThan 0
    }
}
Describe 'PSExec/WMI ASR rule alignment (Invoke-SecurityBaseline Step 5)' {
    BeforeAll {
        $script:InvokeSource = Get-Content (Join-Path $script:ModuleRoot 'Public/Invoke-SecurityBaseline.ps1') -Raw -Encoding UTF8
    }

    It 'patches the d1e49aac baseline value before Set-RegistryPolicies consumes the temp file' {
        $script:InvokeSource | Should -Match 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        $patchIndex = $script:InvokeSource.IndexOf('$psexecWmiPolicy[0].Data = [string]$asrRuleAction')
        $tempWriteIndex = $script:InvokeSource.IndexOf('Computer-RegistryPolicies-$([guid]::NewGuid()')
        $patchIndex | Should -BeGreaterThan 0
        $tempWriteIndex | Should -BeGreaterThan $patchIndex
    }

    It 'uses verifier precedence: durable ASR intent first, then the durable QuickAction override' {
        $asrIntentIndex = $script:InvokeSource.IndexOf("'durable ASR intent'")
        $overrideIndex = $script:InvokeSource.IndexOf("'durable QuickAction override'")
        $asrIntentIndex | Should -BeGreaterThan 0
        $overrideIndex | Should -BeGreaterThan $asrIntentIndex
    }

    It 'accepts only the documented Block/Audit actions from either durable source' {
        ([regex]::Matches($script:InvokeSource, [regex]::Escape('.Action -in @(1, 2)'))).Count |
            Should -BeGreaterOrEqual 2
    }

    It 'records the used decision in Details.AsrActionOverrides for the rewritten intent record' {
        $script:InvokeSource |
            Should -Match ([regex]::Escape('$result.Details.AsrActionOverrides = @([PSCustomObject]@{ Guid = $psexecWmiRuleGuid; Action = $asrRuleAction })'))
        $script:InvokeSource | Should -Match ([regex]::Escape('AsrActionOverrides = @()'))
    }

    It 'falls back to the sealed package value when no user decision is recorded' {
        $script:InvokeSource | Should -Match 'keeps the sealed package value'
    }
}

Describe 'Applied-scope verification of the PSExec/WMI ASR expectation' {
    BeforeAll {
        $script:VerifySource = Get-Content (Join-Path $script:RepoRoot 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
    }

    It 'consumes only the transaction-bound SecurityBaseline intent record of the applied session' {
        $script:VerifySource | Should -Match 'authoritativeBaselineAsrOverrides'
        $script:VerifySource | Should -Match 'sourceId -ceq \$appliedSessionId'
        $script:VerifySource | Should -Match "sourceKind -ceq 'ApplySession'"
    }

    It 'patches the baseline registry expectation from the resolved override source' {
        $script:VerifySource | Should -Match 'foreach \(\$override in \$authoritativeBaselineAsrOverrides\)'
        $script:VerifySource | Should -Not -Match 'foreach \(\$override in @\(\$securityBaselineIntent\.asrActionOverrides\)\)'
    }

    It 'loads the intent reader for applied-scope runs too' {
        # The dot-source must sit immediately BEFORE the standalone-only gate,
        # i.e. outside of it, so applied-scope runs get Read-NoIDIntentState too.
        $script:VerifySource | Should -Match '\. \$intentHelperPath\r?\nif \(-not \$appliedScopeRun\) \{'
    }
}
