#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Core/Rollback.ps1')
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityFirewallPolicyState.ps1')
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityFirewallBackup.ps1')
    Set-Item -Path function:Write-Log -Value { param($Level, $Message, $Module); $null = $Level, $Message, $Module }
    function Write-NoIDDetail { param($Message, $ForegroundColor); $null = $Message, $ForegroundColor }
    function Get-AppRuleFixture {
        param([string]$Version = '1.0.0.0', [switch]$Inbound)
        $family = 'Microsoft.GetHelp_8wekyb3d8bbwe'
        $user = 'S-1-5-21-100-200-300-1001'
        $direction = if ($Inbound) { 'In' } else { 'Out' }
        $suffix = if ($Inbound) { 'ServerCapability' } else { 'AllCapabilities' }
        $profiles = if ($Inbound) { 'Profile=Domain|Profile=Private|' } else { 'Profile=Domain|Profile=Private|Profile=Public|' }
        [pscustomobject]@{
            Kind='Value'; Path='FirewallRules'; Name="$family$user-$direction-Allow-$suffix"; Type='String'
            Data="v2.33|Action=Allow|Active=TRUE|Dir=$direction|${profiles}Name=@{Microsoft.GetHelp_${Version}_x64__8wekyb3d8bbwe?ms-resource://Microsoft.GetHelp/Resources/appDisplayName}|PFN=$family|LUOwn=$user|Platform=2:6:2|Platform2=GTEQ|"
        }
    }
    function Get-PolicyFixture {
        param([object[]]$Rules = @(), [string]$Enabled = '1')
        $entries = @(
            [pscustomobject]@{Kind='Key';Path='';Name='';Type='';Data=''},
            [pscustomobject]@{Kind='Key';Path='FirewallRules';Name='';Type='';Data=''},
            [pscustomobject]@{Kind='Value';Path='PublicProfile';Name='EnableFirewall';Type='DWord';Data=$Enabled}
        ) + $Rules
        [pscustomobject]@{SchemaVersion=1;EntryCount=$entries.Count;Entries=$entries}
    }
}

Describe 'Unsealed firewall backup classifies the complete difference' {
    It 'accepts generated <Direction> package rules' -TestCases @(
        @{Direction='outbound'; Inbound=$false}, @{Direction='inbound'; Inbound=$true}
    ) {
        param($Direction, $Inbound)
        $null = $Direction
        Test-AdvancedSecurityWindowsAppFirewallEntry (Get-AppRuleFixture -Inbound:$Inbound) | Should -BeTrue
    }

    It 'classifies a package rule <Change> without weakening exact equivalence' -TestCases @(
        @{Change='addition'}, @{Change='removal'}, @{Change='update'}
    ) {
        param($Change)
        $a = Get-PolicyFixture -Rules @(Get-AppRuleFixture)
        $b = Get-PolicyFixture -Rules @(Get-AppRuleFixture -Version '2.0.0.0')
        if ($Change -eq 'addition') { $a = Get-PolicyFixture }
        if ($Change -eq 'removal') { $b = Get-PolicyFixture }
        $diff = Get-AdvancedSecurityFirewallPolicyDifference $a $b
        $diff.AppRulesOnly | Should -BeTrue
        $diff.Equivalent | Should -BeFalse
        $diff.ChangedEntries | Should -Be 1
        $script:ExactReference = $a; $script:ExactCandidate = $b
        Mock Get-AdvancedSecurityFirewallPolicyState { $script:ExactReference } -ParameterFilter { $PolicyFilePath -eq 'a.wfw' }
        Mock Get-AdvancedSecurityFirewallPolicyState { $script:ExactCandidate } -ParameterFilter { $PolicyFilePath -eq 'b.wfw' }
        Assert-AdvancedSecurityFirewallPolicyEquivalent a.wfw a.wfw | Should -BeTrue
        $expectedError = if ($Change -eq 'update') { '*property Data*' } else { '*entry count changed*' }
        { Assert-AdvancedSecurityFirewallPolicyEquivalent a.wfw b.wfw } | Should -Throw $expectedError
    }

    It 'accepts identical complete inventories as equivalent, without requiring every rule to be a package rule' {
        $a = Get-PolicyFixture
        $diff = Get-AdvancedSecurityFirewallPolicyDifference $a $a
        $diff.Equivalent | Should -BeTrue
        $diff.AppRulesOnly | Should -BeFalse
        $diff.ChangedEntries | Should -Be 0
    }

    It 'keeps arbitrary unchanged value data exact without treating it as a package rule' {
        $rule = Get-AppRuleFixture
        $rule.Data += [char]0
        $a = Get-PolicyFixture -Rules @($rule)
        (Get-AdvancedSecurityFirewallPolicyDifference $a $a).Equivalent | Should -BeTrue
        Test-AdvancedSecurityWindowsAppFirewallEntry $rule | Should -BeFalse
        (Get-AdvancedSecurityFirewallPolicyDifference (Get-PolicyFixture) $a).AppRulesOnly | Should -BeFalse
    }

    It 'rejects mixed app/global drift even when the app change occurs <Position>' -TestCases @(
        @{Position='first'}, @{Position='last'}
    ) {
        param($Position)
        $a = Get-PolicyFixture -Rules @(Get-AppRuleFixture)
        $b = Get-PolicyFixture -Rules @(Get-AppRuleFixture -Version '2.0.0.0') -Enabled '0'
        if ($Position -eq 'first') { [array]::Reverse($a.Entries); [array]::Reverse($b.Entries) }
        $diff = Get-AdvancedSecurityFirewallPolicyDifference $a $b
        $diff.AppRulesOnly | Should -BeFalse
        $diff.ChangedEntries | Should -Be 2
        $diff.OtherChanges | Should -Be 1
    }

    It 'rejects non-package rule <Change>, including beside package changes' -TestCases @(
        @{Change='addition'}, @{Change='removal'}, @{Change='update'}
    ) {
        param($Change)
        $custom = [pscustomobject]@{Kind='Value';Path='FirewallRules';Name='NoIDTest-Drift';Type='String';Data='v2.33|Action=Block|Dir=In|'}
        $a = Get-PolicyFixture -Rules @((Get-AppRuleFixture), $custom)
        $other = $custom.PSObject.Copy(); $other.Data = 'v2.33|Action=Allow|Dir=In|'
        $b = Get-PolicyFixture -Rules @((Get-AppRuleFixture -Version '2.0.0.0'), $other)
        if ($Change -eq 'addition') { $a = Get-PolicyFixture -Rules @(Get-AppRuleFixture) }
        if ($Change -eq 'removal') { $b = Get-PolicyFixture -Rules @(Get-AppRuleFixture -Version '2.0.0.0') }
        $diff = Get-AdvancedSecurityFirewallPolicyDifference $a $b
        $diff.AppRulesOnly | Should -BeFalse
        $diff.OtherChanges | Should -Be 1
    }

    It 'rejects an unproven package rule identity: <Field>' -TestCases @(
        @{Field='Name';Value='NoID_Block_LLMNR'},
        @{Field='Name';Value='{11111111-2222-3333-4444-555555555555}'},
        @{Field='Kind';Value='Key'}, @{Field='Path';Value='AppIso\FirewallRules'},
        @{Field='Path';Value='PublicProfile'}, @{Field='Type';Value='ExpandString'},
        @{Field='Data';Value='v2.33|AppPkgId=S-1-15-2-1-2-3-4-5-6-7|'},
        @{Field='Data';Value='v2.33|App=C:\Program Files\WindowsApps\Example\app.exe|'}
    ) {
        param($Field, $Value)
        $rule = Get-AppRuleFixture
        $rule.$Field = $Value
        Test-AdvancedSecurityWindowsAppFirewallEntry $rule | Should -BeFalse
    }

    It 'rejects malformed or custom package rule fields: <Case>' -TestCases @(
        @{Case='duplicate PFN';Old='Platform2=GTEQ';New='PFN=Microsoft.GetHelp_8wekyb3d8bbwe'},
        @{Case='different PFN';Old='PFN=Microsoft.GetHelp';New='PFN=Microsoft.Other'},
        @{Case='different owner';Old='LUOwn=S-1-5-21-100-200-300-1001';New='LUOwn=S-1-5-21-100-200-300-1002'},
        @{Case='changed action';Old='Action=Allow';New='Action=Block'},
        @{Case='disabled';Old='Active=TRUE';New='Active=FALSE'},
        @{Case='custom executable';Old='Platform2=GTEQ';New='App=C:\custom.exe'},
        @{Case='missing profile';Old='Profile=Public|';New=''},
        @{Case='duplicate profile';Old='Profile=Public';New='Profile=Private'},
        @{Case='wrong direction';Old='Dir=Out';New='Dir=In'}
    ) {
        param($Case, $Old, $New)
        $null = $Case
        $rule = Get-AppRuleFixture
        $rule.Data = $rule.Data.Replace($Old, $New)
        Test-AdvancedSecurityWindowsAppFirewallEntry $rule | Should -BeFalse
        $a = Get-PolicyFixture -Rules @($rule)
        $b = Get-PolicyFixture -Rules @(Get-AppRuleFixture)
        (Get-AdvancedSecurityFirewallPolicyDifference $a $b).AppRulesOnly | Should -BeFalse
        (Get-AdvancedSecurityFirewallPolicyDifference $b $a).AppRulesOnly | Should -BeFalse
    }

    It 'rejects changed keys and malformed snapshots: <Case>' -TestCases @(
        @{Case='schema'}, @{Case='count'}, @{Case='duplicate'}, @{Case='key'}
    ) {
        param($Case)
        $a = Get-PolicyFixture
        $b = Get-PolicyFixture
        switch ($Case) {
            schema { $b.SchemaVersion = 2 }
            count { $b.EntryCount++ }
            duplicate { $b.Entries += $b.Entries[0]; $b.EntryCount++ }
            key { $b.Entries[1].Path = 'OtherRules' }
        }
        if ($Case -eq 'key') { (Get-AdvancedSecurityFirewallPolicyDifference $a $b).AppRulesOnly | Should -BeFalse }
        else { { Get-AdvancedSecurityFirewallPolicyDifference $a $b } | Should -Throw }
    }
}

Describe 'Firewall backup refresh stays bounded and never modifies sealed artifacts' {
    BeforeEach {
        $script:SavedBackupGlobals = @{}
        foreach ($key in @('BackupBasePath','BackupIndex','CurrentModule','SessionManifest')) {
            $script:SavedBackupGlobals[$key] = (Get-Variable $key -Scope Global).Value
        }
        $script:SavedTemp = $env:TEMP; $script:SavedSystemRoot = $env:SystemRoot
        $env:TEMP = $TestDrive
        # Windows cryptographic providers use SystemRoot even with native
        # process calls mocked. Only supply a path on non-Windows test hosts.
        if (-not $env:SystemRoot) { $env:SystemRoot = $TestDrive }
        $global:BackupBasePath = Join-Path $TestDrive ('Session_' + [guid]::NewGuid().ToString('N'))
        $modulePath = Join-Path $global:BackupBasePath 'AdvancedSecurity'
        $null = New-Item -ItemType Directory -Path $modulePath -Force
        $script:FirewallPath = Join-Path $modulePath 'AdvancedSecurity_FirewallPolicy.wfw'
        Set-Content $script:FirewallPath 'initial'
        $global:CurrentModule = 'AdvancedSecurity'
        $global:BackupIndex = @()
        $global:SessionManifest = @{
            schemaVersion=2;sessionId=(Split-Path $global:BackupBasePath -Leaf);modules=@();sharedArtifacts=@()
            totalItems=0;restorable=$true;displayName='';sessionType='manual'
            frameworkVersion='2.2.6';timestamp='2026-01-01T00:00:00.0000000Z'
        }
        $null = Register-BackupFile -FilePath $script:FirewallPath -Type FirewallPolicy -Name AdvancedSecurity_FirewallPolicy -Target LocalFirewallPolicy
        $script:ExportCount = 0
        $script:ValidateCount = 0
        $script:ExportStates = @('app1','app1')
        Mock Get-AdvancedSecurityFirewallPolicyState {
            $label = (Get-Content -LiteralPath $PolicyFilePath -Raw).Trim()
            $version = if ($label -eq 'initial') { '1.0.0.0' } else { $label }
            Get-PolicyFixture -Rules @(Get-AppRuleFixture -Version $version) -Enabled $(if ($label -eq 'other') { '0' } else { '1' })
        }
        Mock Start-Process {
            $destination = $ArgumentList[2].Trim('"')
            # Native netsh export refuses to overwrite an existing file.
            if (Test-Path -LiteralPath $destination) { return [pscustomobject]@{ExitCode=1} }
            Set-Content -LiteralPath $destination -Value $script:ExportStates[$script:ExportCount]
            $script:ExportCount++
            [pscustomobject]@{ExitCode=0}
        }
        Mock Start-Sleep {}
    }
    AfterEach {
        foreach ($key in $script:SavedBackupGlobals.Keys) { Set-Variable $key $script:SavedBackupGlobals[$key] -Scope Global }
        $env:TEMP = $script:SavedTemp; $env:SystemRoot = $script:SavedSystemRoot
    }

    It 'succeeds on the second export, rechecks other prestates and seals the replacement hash once' {
        Sync-AdvancedSecurityFirewallBackup $script:FirewallPath -ValidateOtherPrestate { $script:ValidateCount++ } | Should -BeTrue
        $script:ExportCount | Should -Be 2
        $script:ValidateCount | Should -Be 2
        (Get-Content $script:FirewallPath -Raw).Trim() | Should -Be 'app1'
        $global:BackupIndex.Count | Should -Be 1
        Complete-ModuleBackup -ItemsBackedUp 1 -Status Success | Should -BeTrue
        $manifest = Get-SessionManifest $global:BackupBasePath
        $manifest.modules.Count | Should -Be 1
        $manifest.modules[0].artifacts[0].sha256 | Should -Be (Get-FileHash $script:FirewallPath).Hash.ToLowerInvariant()
        @(Get-ChildItem $TestDrive -Filter '*Incomplete*').Count | Should -Be 0
    }

    It 'does not replace an equivalent snapshot' {
        $script:ExportStates = @('initial')
        Sync-AdvancedSecurityFirewallBackup $script:FirewallPath | Should -BeTrue
        Should -Invoke Start-Sleep -Times 0 -Exactly
        (Get-Content $script:FirewallPath -Raw).Trim() | Should -Be 'initial'
    }

    It 'exhausts three refreshes and leaves the backup unsealed' {
        $script:ExportStates = @('app1','app2','app3','app4')
        { Sync-AdvancedSecurityFirewallBackup $script:FirewallPath } | Should -Throw '*did not stabilize after 3*'
        $script:ExportCount | Should -Be 4
        $global:SessionManifest.modules.Count | Should -Be 0
        (Get-Content $script:FirewallPath -Raw).Trim() | Should -Be 'app3'
    }

    It 'rejects non-app drift before any replacement' {
        $script:ExportStates = @('other')
        { Sync-AdvancedSecurityFirewallBackup $script:FirewallPath } | Should -Throw '*non-app changes*'
        $script:ExportCount | Should -Be 1
        (Get-Content $script:FirewallPath -Raw).Trim() | Should -Be 'initial'
    }

    It 'rejects non-firewall drift on the retry before exporting again' {
        { Sync-AdvancedSecurityFirewallBackup $script:FirewallPath -ValidateOtherPrestate {
            $script:ValidateCount++
            if ($script:ValidateCount -eq 2) { throw 'Other prestate changed' }
        } } | Should -Throw '*Other prestate changed*'
        $script:ExportCount | Should -Be 1
        $global:SessionManifest.modules.Count | Should -Be 0
    }

    It 'rejects a sealed backup in <Authority>' -TestCases @(@{Authority='memory'}, @{Authority='disk'}) {
        param($Authority)
        if ($Authority -eq 'memory') { $global:SessionManifest.modules = @(@{name='AdvancedSecurity'}) }
        else { '{"modules":[{"name":"AdvancedSecurity"}]}' | Set-Content (Join-Path $global:BackupBasePath 'manifest.json') }
        { Sync-AdvancedSecurityFirewallBackup $script:FirewallPath } | Should -Throw '*seal*'
        $script:ExportCount | Should -Be 0
        (Get-Content $script:FirewallPath -Raw).Trim() | Should -Be 'initial'
    }

    It 'rechecks seal ownership immediately before replacement' {
        { Sync-AdvancedSecurityFirewallBackup $script:FirewallPath -ValidateOtherPrestate {
            $global:SessionManifest.modules = @(@{name='AdvancedSecurity'})
        } } | Should -Throw '*unsealed*'
        (Get-Content $script:FirewallPath -Raw).Trim() | Should -Be 'initial'
    }

    It 'rejects a wrong path or inactive module before native execution' {
        { Sync-AdvancedSecurityFirewallBackup (Join-Path $TestDrive 'other.wfw') } | Should -Throw '*outside*'
        $global:CurrentModule = ''
        { Sync-AdvancedSecurityFirewallBackup $script:FirewallPath } | Should -Throw '*active*'
        $script:ExportCount | Should -Be 0
    }

    It 'cleans temporary exports when native export fails' {
        Mock Start-Process { [pscustomobject]@{ExitCode=1} }
        { Sync-AdvancedSecurityFirewallBackup $script:FirewallPath } | Should -Throw '*export failed*'
        @(Get-ChildItem $TestDrive -Filter 'NoID_FirewallPreApply_*').Count | Should -Be 0
        (Get-Content $script:FirewallPath -Raw).Trim() | Should -Be 'initial'
    }
}
