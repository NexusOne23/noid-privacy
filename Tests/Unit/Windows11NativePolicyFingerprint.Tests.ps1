#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repoRoot 'Tests/Windows11/Windows11NativePolicyFingerprint.ps1')
    $script:AuditHeader = 'Computer,Target,Subcategory,Guid,Inclusion,Exclusion,Flags'
    $script:AuditRow = 'test-machine,System,"Localized, description",{0cce922b-69ae-11d9-bed3-505054503030},Localized,,1'
    $script:OptionRow = 'test-machine,,Option:CrashOnAuditFail,,Localized,,0'
    $script:AuditCsv = @($script:AuditHeader, $script:AuditRow, $script:OptionRow) -join "`r`n"
    $script:SecurityInf = @('[Unicode]', 'Unicode=yes', '[System Access]', 'MinimumPasswordLength = 14',
        '[Privilege Rights]', 'SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551', 'SeDebugPrivilege =',
        '[Version]', 'Revision=1') -join "`r`n"
}

Describe 'Independent local Group Policy filesystem fingerprint' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        $script:GpoRoot = Join-Path $TestDrive 'GroupPolicy'
        $null = New-Item -ItemType Directory -Path (Join-Path $script:GpoRoot 'Machine') -Force
        [IO.File]::WriteAllText((Join-Path $script:GpoRoot 'gpt.ini'), "[General]`r`nVersion=1`r`n")
    }

    It 'reads stable content without storing raw policy contents or identities' {
        $path = Join-Path $script:GpoRoot 'Machine\Registry.pol'
        [IO.File]::WriteAllText($path, 'Private fixture contents')
        $before = Get-Windows11LocalGroupPolicyFingerprintState -RootPath $script:GpoRoot
        $after = Get-Windows11LocalGroupPolicyFingerprintState -RootPath $script:GpoRoot
        ($after | ConvertTo-Json -Depth 8 -Compress) | Should -BeExactly ($before | ConvertTo-Json -Depth 8 -Compress)
        $before.Entries.Count | Should -Be 4
        ($before | ConvertTo-Json -Depth 8 -Compress) | Should -Not -Match 'Private fixture contents|S-1-'
        @($before.Entries | Where-Object Path -eq 'Machine\Registry.pol')[0].Sha256 |
            Should -BeExactly (Get-FileHash $path).Hash.ToLowerInvariant()
    }

    It 'detects <Change> instead of treating native bookkeeping as restored' -TestCases @(
        @{Change='GPO revision'}, @{Change='new empty policy file'},
        @{Change='empty directory'}, @{Change='policy bytes'}, @{Change='access control'}
    ) {
        param($Change)
        $path = Join-Path $script:GpoRoot 'gpt.ini'
        $before = Get-Windows11LocalGroupPolicyFingerprintState -RootPath $script:GpoRoot | ConvertTo-Json -Depth 8 -Compress
        switch -Exact ($Change) {
            'GPO revision' { [IO.File]::WriteAllText($path, "[General]`r`nVersion=2`r`n") }
            'new empty policy file' { [IO.File]::WriteAllBytes((Join-Path $script:GpoRoot 'Machine\Registry.pol'), [byte[]]@(80,82,101,103,1,0,0,0)) }
            'empty directory' { $null = New-Item -ItemType Directory -Path (Join-Path $script:GpoRoot 'User') }
            'policy bytes' { [IO.File]::WriteAllText($path, "[General]`r`nVersion=1`r`nUnknown=preserve`r`n") }
            'access control' {
                $acl = Get-Acl -LiteralPath $path
                $acl.SetAccessRuleProtection($true, $true)
                Set-Acl -LiteralPath $path -AclObject $acl
            }
        }
        (Get-Windows11LocalGroupPolicyFingerprintState -RootPath $script:GpoRoot | ConvertTo-Json -Depth 8 -Compress) |
            Should -Not -BeExactly $before
    }

    It 'distinguishes an absent policy root from an existing empty directory' {
        $path = Join-Path $TestDrive 'AbsentPolicyRoot'
        $absent = Get-Windows11LocalGroupPolicyFingerprintState -RootPath $path
        $absent.Present | Should -BeFalse
        $absent.Entries.Count | Should -Be 0
        $null = New-Item -ItemType Directory -Path $path
        $present = Get-Windows11LocalGroupPolicyFingerprintState -RootPath $path
        $present.Present | Should -BeTrue
        $present.Entries.Count | Should -Be 1
    }
}

Describe 'Independent native audit-policy fingerprint reader' {
    It 'keeps GUIDs, options and numeric flags while excluding machine names and localized captions' {
        $state = @(ConvertFrom-Windows11AuditPolicyCsv -Content $script:AuditCsv)
        $state.Count | Should -Be 2
        ($state | ConvertTo-Json -Compress) | Should -Not -Match 'test-machine|Localized'
        @($state | Where-Object Identity -eq '0cce922b-69ae-11d9-bed3-505054503030')[0].Flags | Should -Be 1
        @($state | Where-Object Identity -eq 'Option:CrashOnAuditFail')[0].Flags | Should -Be 0
        $renamed = $script:AuditCsv.Replace('test-machine', 'another-machine').Replace('Localized', 'Other language')
        (ConvertFrom-Windows11AuditPolicyCsv -Content $renamed | ConvertTo-Json -Compress) |
            Should -BeExactly ($state | ConvertTo-Json -Compress)
    }

    It 'detects changed system policy, per-user policy and audit options' {
        $before = ConvertFrom-Windows11AuditPolicyCsv -Content $script:AuditCsv | ConvertTo-Json -Compress
        foreach ($changed in @(
            $script:AuditCsv.Replace(',,1', ',,3'),
            $script:AuditCsv.Replace(',,0', ',,1'),
            ($script:AuditCsv + "`r`n" + $script:AuditRow.Replace(',System,', ',S-1-5-21-1-2-3-1001,').Replace(',,1', ',,4'))
        )) {
            (ConvertFrom-Windows11AuditPolicyCsv -Content $changed | ConvertTo-Json -Compress) | Should -Not -Be $before
        }
    }

    It 'rejects an invalid native CSV contract: <Kind>' -TestCases @(
        @{ Kind='extra column'; Suffix=',extra'; Row=$null }
        @{ Kind='missing column'; Suffix=''; Row='test-machine,System,label,{0cce922b-69ae-11d9-bed3-505054503030},,1' }
        @{ Kind='invalid GUID'; Suffix=''; Row='test-machine,System,label,not-a-guid,,,1' }
        @{ Kind='invalid option'; Suffix=''; Row='test-machine,,not-an-option,,,,0' }
        @{ Kind='invalid flags'; Suffix=''; Row='test-machine,System,label,{0cce922b-69ae-11d9-bed3-505054503030},,,unknown' }
    ) {
        param($Kind,$Suffix,$Row)
        $null=$Kind
        $line = if ($null -eq $Row) { $script:AuditRow + $Suffix } else { $Row }
        { ConvertFrom-Windows11AuditPolicyCsv -Content ($script:AuditHeader + "`r`n" + $line) } | Should -Throw
    }

    It 'rejects duplicates and exports without any subcategories' {
        { ConvertFrom-Windows11AuditPolicyCsv -Content ($script:AuditCsv + "`r`n" + $script:AuditRow) } | Should -Throw
        { ConvertFrom-Windows11AuditPolicyCsv -Content ($script:AuditHeader + "`r`n" + $script:OptionRow) } | Should -Throw
    }
}

Describe 'Independent native security-policy fingerprint reader' {
    It 'ignores only principal ordering and omitted empty assignments' {
        $before = ConvertFrom-Windows11SecurityPolicyInf -Content $script:SecurityInf | ConvertTo-Json -Compress
        $equivalent = $script:SecurityInf.Replace('*S-1-5-32-544,*S-1-5-32-551', '*S-1-5-32-551, *S-1-5-32-544').Replace("SeDebugPrivilege =`r`n", '')
        (ConvertFrom-Windows11SecurityPolicyInf -Content $equivalent | ConvertTo-Json -Compress) | Should -BeExactly $before
    }

    It 'detects changes to password policy and privilege membership' {
        $before = ConvertFrom-Windows11SecurityPolicyInf -Content $script:SecurityInf | ConvertTo-Json -Compress
        foreach ($changed in @($script:SecurityInf.Replace('= 14', '= 13'),
            $script:SecurityInf.Replace(',*S-1-5-32-551', ''),
            $script:SecurityInf.Replace('SeDebugPrivilege =', 'SeDebugPrivilege = *S-1-5-32-544'))) {
            (ConvertFrom-Windows11SecurityPolicyInf -Content $changed | ConvertTo-Json -Compress) | Should -Not -Be $before
        }
    }

    It 'rejects missing sections, ambiguous settings and malformed owned entries' {
        foreach ($invalid in @(
            $script:SecurityInf.Replace('[Privilege Rights]', '[Other]'),
            $script:SecurityInf.Replace('MinimumPasswordLength = 14', 'malformed'),
            ($script:SecurityInf + "`r`n[System Access]`r`nMinimumPasswordLength = 14"),
            $script:SecurityInf.Replace('MinimumPasswordLength = 14', "MinimumPasswordLength = 14`r`nminimumpasswordlength = 13")
        )) {
            { ConvertFrom-Windows11SecurityPolicyInf -Content $invalid } | Should -Throw
        }
    }
}

Describe 'Independent native policy export exit evidence' {
    BeforeEach {
        $script:HadPolicyExitCode = Test-Path variable:global:LASTEXITCODE
        $script:SavedPolicyExitCode = Get-Variable LASTEXITCODE -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        $script:SavedPolicySystemRoot = $env:SystemRoot
        if (-not $env:SystemRoot) { $env:SystemRoot = $TestDrive }
        $script:ExportDirectory = (New-Item -Path (Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))) -ItemType Directory).FullName
        $script:PolicyFailure = 'none'
        $script:PolicyCalls = [Collections.Generic.List[string]]::new()
        function Invoke-FixtureAuditPolicyExport {
            $script:PolicyCalls.Add('audit')
            if ($script:PolicyFailure -cne 'audit-no-file') {
                Set-Content -LiteralPath ([string]$args[1]).Substring('/file:'.Length) -Value $script:AuditCsv -Encoding Ascii
            }
            if ($script:PolicyFailure -cne 'audit-no-exit-code') { $global:LASTEXITCODE = if ($script:PolicyFailure -ceq 'audit-nonzero') { 5 } else { 0 } }
        }
        function Invoke-FixtureSecurityPolicyExport {
            $script:PolicyCalls.Add('security')
            if ($script:PolicyFailure -cne 'security-no-file') {
                Set-Content -LiteralPath $args[2] -Value $script:SecurityInf -Encoding Unicode
            }
            if ($script:PolicyFailure -cne 'security-no-exit-code') { $global:LASTEXITCODE = if ($script:PolicyFailure -ceq 'security-nonzero') { 5 } else { 0 } }
        }
        Mock Join-Path { 'Invoke-FixtureAuditPolicyExport' } -ParameterFilter { $ChildPath -ceq 'System32\auditpol.exe' }
        Mock Join-Path { 'Invoke-FixtureSecurityPolicyExport' } -ParameterFilter { $ChildPath -ceq 'System32\secedit.exe' }
        Mock Start-Process { throw 'Independent exports must retain native exit evidence directly' }
    }

    AfterEach {
        $env:SystemRoot = $script:SavedPolicySystemRoot
        if ($script:HadPolicyExitCode) { $global:LASTEXITCODE = $script:SavedPolicyExitCode }
        else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
    }

    It 'parses both successful exports and cleans their private temporary files' {
        $state = Get-Windows11NativePolicyFingerprintState -TemporaryDirectory $script:ExportDirectory
        @($state.AuditPolicies).Count | Should -Be 2
        @($state.SecurityPolicies).Count | Should -Be 2
        $script:PolicyCalls -join ',' | Should -BeExactly 'audit,security'
        @(Get-ChildItem $script:ExportDirectory -Force).Count | Should -Be 0
    }

    It 'rejects <Failure> and never reuses an earlier successful exit code' -TestCases @(
        @{Failure='audit-nonzero'}, @{Failure='audit-no-exit-code'}, @{Failure='audit-no-file'},
        @{Failure='security-nonzero'}, @{Failure='security-no-exit-code'}, @{Failure='security-no-file'}
    ) {
        param($Failure)
        $script:PolicyFailure = $Failure
        $global:LASTEXITCODE = 0
        { Get-Windows11NativePolicyFingerprintState -TemporaryDirectory $script:ExportDirectory } | Should -Throw
        $script:PolicyCalls.Count | Should -Be $(if ($Failure.StartsWith('audit-')) { 1 } else { 2 })
        @(Get-ChildItem $script:ExportDirectory -Force).Count | Should -Be 0
    }
}
