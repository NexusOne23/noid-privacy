#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Core/Rollback.ps1')
    . (Join-Path $repo 'Modules/SecurityBaseline/Private/Restore-SecurityTemplate.ps1')
    . (Join-Path $repo 'Modules/SecurityBaseline/Private/Backup-SecurityTemplate.ps1')
    . (Join-Path $repo 'Modules/SecurityBaseline/Private/Set-SecurityTemplate.ps1')
    $script:TemplateSource = Join-Path $repo 'Modules/SecurityBaseline/ParsedSettings/SecurityTemplates.json'
    if (-not (Get-Command Get-Service -ErrorAction SilentlyContinue)) {
        # Supply the missing command only for isolated non-Windows tests.
        Set-Item -Path Function:Get-Service -Value {
            [CmdletBinding()] param([string]$Name)
            throw "The native service query must be mocked: $Name"
        }
    }
    Set-Item -Path Function:Write-Log -Value { param($Level, $Message, $Module) $null = $Level, $Message, $Module }
    $templates = Get-Content (Join-Path $repo 'Modules/SecurityBaseline/ParsedSettings/SecurityTemplates.json') -Raw | ConvertFrom-Json
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($line in @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1')) { $lines.Add($line) }
    foreach ($sectionName in @('System Access', 'Privilege Rights')) {
        $lines.Add("[$sectionName]")
        $seen = @{}
        foreach ($group in $templates.PSObject.Properties) {
            $section = $group.Value.PSObject.Properties[$sectionName]
            if ($null -eq $section) { continue }
            foreach ($entry in $section.Value.PSObject.Properties) {
                if (-not $seen.ContainsKey($entry.Name)) {
                    $lines.Add($entry.Name + ' = ' + [string]$entry.Value)
                    $seen[$entry.Name] = $true
                }
            }
        }
    }
    $script:ValidInf = $lines -join "`r`n"
    $script:Artifact = [pscustomobject]@{type='SecurityBaseline'; name='SecurityTemplate'; target='SecurityTemplate'}

    $tokens = $null
    $parseErrors = $null
    $verifierAst = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repo 'Tools/Verify-Complete-Hardening.ps1'), [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Verifier parser failed' }
    $exportFunction = @($verifierAst.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Export-SecurityTemplateForVerification'
    }, $true))
    if ($exportFunction.Count -ne 1) { throw 'Expected one verifier export boundary' }
    . ([scriptblock]::Create($exportFunction[0].Extent.Text))
}

Describe 'Security-template sections before native import' {
    BeforeEach {
        Set-StrictMode -Version Latest
        $script:InfPath = Join-Path $TestDrive 'security.inf'
    }

    It 'accepts the complete owned template inventory as a positive control' {
        Set-Content -LiteralPath $script:InfPath -Value $script:ValidInf -Encoding Unicode
        { Assert-ArtifactContentBinding -Artifact $script:Artifact -ArtifactPath $script:InfPath } | Should -Not -Throw
    }

    It 'rejects <Label> outside the owned sections' -TestCases @(
        @{Label='an ordinary registry section'; Header='[Registry Values]'},
        @{Label='an indented registry section'; Header='  [Registry Values]'},
        @{Label='a tab-indented service section'; Header="`t[Service General Setting]"},
        @{Label='an indented file-security section'; Header=' [File Security]'},
        @{Label='a malformed section header'; Header=' [Registry Values] trailing'},
        @{Label='a duplicate metadata section'; Header='[Unicode]'}
    ) {
        param($Label, $Header)
        $null = $Label
        Set-Content -LiteralPath $script:InfPath -Value ($script:ValidInf + "`r`n" + $Header + "`r`n") -Encoding Unicode
        { Assert-ArtifactContentBinding -Artifact $script:Artifact -ArtifactPath $script:InfPath } | Should -Throw
    }

    It 'rejects an indented foreign section in direct restore before starting secedit' {
        Set-Content -LiteralPath $script:InfPath -Value ($script:ValidInf + "`r`n  [Registry Values]`r`n") -Encoding Unicode
        function secedit.exe { throw 'Native import must not run' }
        Mock secedit.exe { throw 'Native import must not run' }
        $result = Restore-SecurityTemplate -BackupPath $script:InfPath -Confirm:$false -ErrorAction SilentlyContinue
        $result.Success | Should -BeFalse
        $result.Errors -join '; ' | Should -Match 'unexpected section'
        Should -Invoke secedit.exe -Times 0 -Exactly
    }
}

Describe 'Security-template BAVR native exit evidence' {
    BeforeEach {
        $script:HadBavrExitCode = Test-Path variable:global:LASTEXITCODE
        $script:SavedBavrExitCode = Get-Variable LASTEXITCODE -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        $script:SavedBavrTemp = $env:TEMP
        $caseRoot = New-Item -Path (Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))) -ItemType Directory
        $env:TEMP = $caseRoot.FullName
        $script:BavrBackup = Join-Path $caseRoot.FullName 'original backup with spaces.inf'
        Set-Content -LiteralPath $script:BavrBackup -Value $script:ValidInf -Encoding Unicode
        $script:BavrBackupHash = (Get-FileHash $script:BavrBackup).Hash
        $script:BavrPlan = Join-Path $caseRoot.FullName 'plan with spaces.json'
        @{Fixture=@{'System Access'=@{MinimumPasswordLength='14'};'Privilege Rights'=@{SeDebugPrivilege=''}}} |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:BavrPlan
        $script:BavrMode = 'success'
        $script:BavrFailureStage = '/export'
        $script:BavrNativeInf = $script:ValidInf + "`r`n[Registry Values]`r`nUnrelated=4,1"
        $script:BavrNativeCalls = [Collections.Generic.List[object]]::new()
        Mock Get-Service { @() }
        Mock Start-Process { throw 'Native exit evidence must not reopen a process object' }
        function secedit.exe {
            $nativeArgs = @($args)
            $script:BavrNativeCalls.Add($nativeArgs)
            $nativeStage = [string]$nativeArgs[0]
            $mode = if ($nativeStage -ceq $script:BavrFailureStage) { $script:BavrMode } else { 'success' }
            if ($mode -ceq 'launch-failure') { throw 'Injected native launch failure' }
            $cfg = [string]$nativeArgs[[Array]::IndexOf($nativeArgs, '/cfg') + 1]
            $log = [string]$nativeArgs[[Array]::IndexOf($nativeArgs, '/log') + 1]
            Set-Content -LiteralPath $log -Value 'fixture log'
            if ($nativeStage -ceq '/configure') {
                $script:BavrNativeInf = Get-Content -LiteralPath $cfg -Raw
            }
            elseif ($mode -cne 'no-file') {
                $text = if ($mode -ceq 'mismatch') { $script:BavrNativeInf -replace '(?m)^MinimumPasswordLength\s*=.*$', 'MinimumPasswordLength=99' } else { $script:BavrNativeInf }
                Set-Content -LiteralPath $cfg -Value $text -Encoding Unicode
            }
            if ($mode -cne 'no-exit-code') { $global:LASTEXITCODE = if ($mode -ceq 'nonzero') { 5 } else { 0 } }
            'Native output must not contaminate the result object'
        }
    }

    AfterEach {
        $env:TEMP = $script:SavedBavrTemp
        if ($script:HadBavrExitCode) { $global:LASTEXITCODE = $script:SavedBavrExitCode }
        else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
    }

    It 'backs up and filters the complete owned inventory after a successful export' {
        $path = Join-Path $env:TEMP 'new backup with spaces.inf'
        $result = Backup-SecurityTemplate -BackupPath $path -SecurityTemplatePath $script:TemplateSource -Confirm:$false
        $result.Success | Should -BeTrue
        $result.Errors.Count | Should -Be 0
        { Assert-ArtifactContentBinding -Artifact $script:Artifact -ArtifactPath $path } | Should -Not -Throw
        Get-Content -LiteralPath $path -Raw | Should -Not -Match 'Unrelated|\[Registry Values\]'
        $script:BavrNativeCalls.Count | Should -Be 1
        $script:BavrNativeCalls[0][2] | Should -BeExactly $path
    }

    It 'counts applied settings only after the generated template matches the native export' {
        $result = Set-SecurityTemplate -SecurityTemplatePath $script:BavrPlan -ServiceNamesWithSealedPrestate @() -Confirm:$false
        $result.Success | Should -BeTrue
        $result.SettingsApplied | Should -Be 2
        $result.SectionsApplied | Should -Be 2
        $script:BavrNativeCalls.Count | Should -Be 2
    }

    It 'restores and verifies the original template without changing its bytes' {
        $result = Restore-SecurityTemplate -BackupPath $script:BavrBackup -Confirm:$false
        $result.Success | Should -BeTrue
        $script:BavrNativeCalls.Count | Should -Be 2
        $script:BavrNativeCalls[0][4] | Should -BeExactly $script:BavrBackup
        (Get-FileHash $script:BavrBackup).Hash | Should -BeExactly $script:BavrBackupHash
    }

    It 'does not claim a backup after <Mode>' -TestCases @(
        @{Mode='nonzero'}, @{Mode='no-exit-code'}, @{Mode='no-file'}, @{Mode='launch-failure'}
    ) {
        param($Mode)
        $script:BavrMode = $Mode
        $global:LASTEXITCODE = 0
        $result = Backup-SecurityTemplate -BackupPath (Join-Path $env:TEMP 'failed backup.inf') -SecurityTemplatePath $script:TemplateSource -Confirm:$false -ErrorAction SilentlyContinue
        $result.Success | Should -BeFalse
        $result.Errors.Count | Should -BeGreaterThan 0
    }

    It 'does not claim <Operation> success after <Stage> <Mode>' -TestCases @(
        foreach ($operation in @('Apply', 'Restore')) {
            foreach ($mode in @('nonzero', 'no-exit-code', 'launch-failure')) {
                @{Operation=$operation; Stage='/configure'; Mode=$mode}
            }
            foreach ($mode in @('nonzero', 'no-exit-code', 'no-file', 'launch-failure', 'mismatch')) {
                @{Operation=$operation; Stage='/export'; Mode=$mode}
            }
        }
    ) {
        param($Operation, $Stage, $Mode)
        $script:BavrMode = $Mode
        $script:BavrFailureStage = $Stage
        $global:LASTEXITCODE = 0
        if ($Operation -ceq 'Apply') {
            $result = Set-SecurityTemplate -SecurityTemplatePath $script:BavrPlan -ServiceNamesWithSealedPrestate @() -Confirm:$false -ErrorAction SilentlyContinue
            $result.SettingsApplied | Should -Be 0
            $result.SectionsApplied | Should -Be 0
        }
        else {
            $result = Restore-SecurityTemplate -BackupPath $script:BavrBackup -Confirm:$false -ErrorAction SilentlyContinue
        }
        $result.Success | Should -BeFalse
        $result.Errors.Count | Should -BeGreaterThan 0
        $script:BavrNativeCalls.Count | Should -Be $(if ($Stage -ceq '/configure') { 1 } else { 2 })
        (Get-FileHash $script:BavrBackup).Hash | Should -BeExactly $script:BavrBackupHash
    }
}

Describe 'Standalone security-template export exit evidence' {
    BeforeEach {
        $script:HadNativeExitCode = Test-Path variable:global:LASTEXITCODE
        $script:SavedNativeExitCode = Get-Variable LASTEXITCODE -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        $caseRoot = New-Item -Path (Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))) -ItemType Directory
        $script:ExportPath = Join-Path $caseRoot.FullName 'export with spaces.inf'
        $script:ExportLog = Join-Path $caseRoot.FullName 'export with spaces.log'
        $script:NativeExportMode = 'success'
        function secedit.exe {
            $script:NativeExportArguments = @($args)
            if ($script:NativeExportMode -eq 'launch-failure') { throw 'Native launch failed' }
            if ($script:NativeExportMode -ne 'no-file') {
                Set-Content -LiteralPath $args[2] -Value '[System Access]' -Encoding Unicode
            }
            if ($script:NativeExportMode -ne 'no-exit-code') {
                $global:LASTEXITCODE = if ($script:NativeExportMode -eq 'nonzero') { 5 } else { 0 }
            }
            'Native console output must not escape the helper'
        }
        Mock Start-Process { throw 'Process-object observation must not be used for this export' }
    }

    AfterEach {
        if ($script:HadNativeExitCode) { $global:LASTEXITCODE = $script:SavedNativeExitCode }
        else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
    }

    It 'accepts exit zero with a file and passes space-containing paths as single arguments' {
        @(Export-SecurityTemplateForVerification -Path $script:ExportPath -LogPath $script:ExportLog).Count | Should -Be 0
        @($script:NativeExportArguments).Count | Should -Be 6
        $script:NativeExportArguments[2] | Should -BeExactly $script:ExportPath
        $script:NativeExportArguments[4] | Should -BeExactly $script:ExportLog
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'rejects <Mode> even with an inherited successful exit code' -TestCases @(
        @{Mode='nonzero'}, @{Mode='no-file'}, @{Mode='no-exit-code'}, @{Mode='launch-failure'}
    ) {
        param($Mode)
        $script:NativeExportMode = $Mode
        $global:LASTEXITCODE = 0
        { Export-SecurityTemplateForVerification -Path $script:ExportPath -LogPath $script:ExportLog } | Should -Throw
        Should -Invoke Start-Process -Times 0 -Exactly
    }
}
