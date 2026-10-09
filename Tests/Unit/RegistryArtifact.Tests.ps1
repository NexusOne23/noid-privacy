#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repoRoot 'Core/Rollback.ps1')
    Set-Item -Path Function:Write-Log -Value { param($Level, $Message, $Module) $null = $Level, $Message, $Module }
    function Write-ErrorLog { param($Message, $Module, $ErrorRecord) $null = $Message, $Module, $ErrorRecord }
}

Describe 'Registry artifact validation before native import' {
    BeforeEach {
        $script:ArtifactPath = Join-Path $TestDrive 'backup.reg'
        $script:Target = 'HKLM:\SOFTWARE\Classes\ms-copilot'
        $script:Artifact = [PSCustomObject]@{ type = 'Registry'; target = $script:Target }
        Mock Write-Log { }
        Mock Write-ErrorLog { }
        Mock Start-Process { throw 'Native mutation must never be reached by rejected input' }
    }

    It 'accepts an exported empty root and an ordinary subtree with values' {
        foreach ($extraLines in @(
                @(''),
                @('"URL Protocol"=""', '', '[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-copilot\shell\open\command]', '@="example.exe"')
            )) {
            (@('Windows Registry Editor Version 5.00', '', '[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-copilot]') + $extraLines) |
                Set-Content -LiteralPath $script:ArtifactPath -Encoding Unicode
            { Assert-ArtifactContentBinding -Artifact $script:Artifact -ArtifactPath $script:ArtifactPath } |
                Should -Not -Throw
        }
    }

    It 'rejects <Label> before native import' -TestCases @(
        @{ Label = 'a deletion outside the sealed subtree'; Directive = '[-HKEY_LOCAL_MACHINE\SOFTWARE\NoIDCanary]' }
        @{ Label = 'a deletion inside an exported subtree'; Directive = '[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-copilot\Child]' }
        @{ Label = 'an indented foreign key'; Directive = '  [HKEY_LOCAL_MACHINE\SOFTWARE\NoIDCanary]' }
        @{ Label = 'a lowercase foreign hive'; Directive = '[hkey_local_machine\SOFTWARE\NoIDCanary]' }
        @{ Label = 'a foreign header with trailing text'; Directive = '[HKEY_LOCAL_MACHINE\SOFTWARE\NoIDCanary] ; extra' }
        @{ Label = 'a foreign header after a bare carriage return'; Directive = "`r[HKEY_LOCAL_MACHINE\SOFTWARE\NoIDCanary]" }
    ) {
        param($Label, $Directive)
        $null = $Label
        @('Windows Registry Editor Version 5.00', '', '[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-copilot]', $Directive) |
            Set-Content -LiteralPath $script:ArtifactPath -Encoding Unicode

        { Assert-ArtifactContentBinding -Artifact $script:Artifact -ArtifactPath $script:ArtifactPath } |
            Should -Throw
        Restore-FromBackup -BackupFile $script:ArtifactPath -Type Registry -ExpectedTarget $script:Target |
            Should -BeFalse
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'rejects a missing export signature before native import' {
        '[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-copilot]' |
            Set-Content -LiteralPath $script:ArtifactPath -Encoding Unicode
        { Assert-ArtifactContentBinding -Artifact $script:Artifact -ArtifactPath $script:ArtifactPath } |
            Should -Throw
        Restore-FromBackup -BackupFile $script:ArtifactPath -Type Registry -ExpectedTarget $script:Target |
            Should -BeFalse
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'encodes exported CR/LF data as REG_SZ hex without interpreting its text as a section' {
        # reg.exe export inserts CR before every LF, including LF inside REG_SZ.
        $nativeText = 'a' + "`r`r`n" + '[-HKEY_LOCAL_MACHINE\\Software\\Canary]' + "`r`n" + 'b'
        $export = 'Windows Registry Editor Version 5.00' + "`r`n`r`n" +
            '[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-copilot]' + "`r`n" +
            '"value"="' + $nativeText + '"' + "`r`n"
        $import = ConvertTo-NoIDRegistryImportContent -Content $export
        $import | Should -Match '"value"=hex\(1\):'
        $import | Should -Not -Match '\[-HKEY_'
        $encoded = ($import -split 'hex\(1\):', 2)[1] -replace '\\\r\n\s*', ''
        $bytes = [byte[]]@($encoded.Trim().Split(',') | ForEach-Object { [Convert]::ToByte($_, 16) })
        [Text.Encoding]::Unicode.GetString($bytes) |
            Should -BeExactly ("a`r`n[-HKEY_LOCAL_MACHINE\Software\Canary]`nb" + [char]0)
        { Assert-NoIDRegistryExport -Content $export -ExpectedTarget $script:Target } | Should -Not -Throw
    }

    It 'preserves quoted names, escaped quotes/backslashes and a bare CR in the value' {
        $export = '"name\\with\"quote"="a\\\"' + "`r" + 'b"' + "`r`n"
        ConvertTo-NoIDRegistryImportContent -Content $export |
            Should -BeExactly ('"name\\with\"quote"=hex(1):61,00,5c,00,22,00,0d,00,62,00,00,00' + "`r`n")
    }

    It 'does not absorb a real deletion after a multiline string' {
        $export = @('Windows Registry Editor Version 5.00', '',
            '[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-copilot]',
            '"value"="first', 'last"', '[-HKEY_LOCAL_MACHINE\Software\Canary]', '') -join "`r`n"
        { Assert-NoIDRegistryExport -Content $export -ExpectedTarget $script:Target } | Should -Throw
    }

    It 'preserves the sealed original and cleans the encoded payload when native import fails: <FailImport>' -TestCases @(
        @{ FailImport = $false }
        @{ FailImport = $true }
    ) {
        param($FailImport)
        $script:FailImport = $FailImport
        $script:CapturedImportPath = $null
        $script:CapturedImportContent = $null
        $export = @('Windows Registry Editor Version 5.00', '',
            '[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-copilot]',
            '"value"="first', 'last"', '') -join "`r`n"
        Set-Content -LiteralPath $script:ArtifactPath -Value $export -Encoding Unicode -NoNewline
        $before = (Get-FileHash -LiteralPath $script:ArtifactPath).Hash
        Mock Start-Process {
            param($ArgumentList, $RedirectStandardOutput, $RedirectStandardError)
            Set-Content -LiteralPath $RedirectStandardOutput -Value ''
            Set-Content -LiteralPath $RedirectStandardError -Value 'test status'
            if ($ArgumentList[0] -eq 'import') {
                $script:CapturedImportPath = ([string]$ArgumentList[1]).Trim('"')
                $script:CapturedImportContent = Get-Content -LiteralPath $script:CapturedImportPath -Raw
                return [PSCustomObject]@{ ExitCode = [int]$script:FailImport }
            }
            # Native value fidelity is separately proven in the Windows gate.
            # This isolated check exercises payload ownership on both exits.
            Copy-Item -LiteralPath $script:ArtifactPath -Destination (([string]$ArgumentList[2]).Trim('"'))
            return [PSCustomObject]@{ ExitCode = 0 }
        }
        $savedTemp = $env:TEMP
        try {
            $env:TEMP = $TestDrive
            Restore-FromBackup -BackupFile $script:ArtifactPath -Type Registry -ExpectedTarget $script:Target |
                Should -Be (-not $FailImport)
        }
        finally { $env:TEMP = $savedTemp }
        $script:CapturedImportPath | Should -Not -BeNullOrEmpty
        $script:CapturedImportPath | Should -Not -Be $script:ArtifactPath
        $script:CapturedImportContent | Should -Match '"value"=hex\(1\):'
        Test-Path -LiteralPath $script:CapturedImportPath | Should -BeFalse
        (Get-FileHash -LiteralPath $script:ArtifactPath).Hash | Should -BeExactly $before
    }
}
