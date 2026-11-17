#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repo 'NoIDPrivacy-Interactive.ps1'), [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Interactive source must parse' }
    $workflow = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-RestoreWorkflow'
    }, $true))
    if ($workflow.Count -ne 1) { throw 'Expected one restore workflow' }
    . ([scriptblock]::Create($workflow[0].Extent.Text))

    function Show-BackupList {
        [pscustomobject]@{
            Restorable=$true; SessionId='SelectionFixture'; Timestamp='2026-09-05'
            FolderPath='SelectionFixture'; TotalItems=3
            Modules=@(@{name='ASR'}, @{name='DNS'}, @{name='AntiAI'})
        }
    }
    function Write-ColorText { param($Text, $Color, [switch]$NoNewline) $null = $Text, $Color, $NoNewline }
    function Write-Header { param($Text) $null = $Text }
    function Write-Step { param($Text, $Status) $null = $Text, $Status }
    function Restore-Session {
        param($SessionPath, [string[]]$ModuleNames, [switch]$SuppressRebootPrompt, [switch]$NoReboot, [string]$ExpectedSettingsFingerprint)
        $null = $SessionPath, $ModuleNames, $SuppressRebootPrompt, $NoReboot, $ExpectedSettingsFingerprint
        throw 'Restore must be mocked in menu tests'
    }
    function Write-Log {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Test placeholder for the engine logger.')]
        [CmdletBinding()] param($Level, $Message, $Module) $null = $Level, $Message, $Module
    }
    $cliAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'NoIDPrivacy.ps1'),[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count){throw 'CLI source must parse'}
    $assignment=$cliAst.Find({param($n)
        $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$restoreSucceeded'
    },$true)
    if(-not $assignment){throw 'Expected the CLI restore transport'}
    $transport=@()
    foreach($statement in $assignment.Parent.Statements) {
        $transport+=$statement.Extent.Text
        if($statement -eq $assignment){break}
    }
    $script:CliRestoreTransport=[scriptblock]::Create($cliAst.ParamBlock.Extent.Text+"`n"+($transport -join "`n")+"`nreturn `$restoreSucceeded")
}

Describe 'CLI restore transports the reviewed Xbox settings fingerprint' {
    BeforeEach {
        Mock Resolve-Path {[pscustomobject]@{Path='ResolvedFixture'}}
        Mock Restore-Session {$true}
    }
    It 'passes the exact supplied fingerprint with noninteractive restore' {
        & $script:CliRestoreTransport -RestoreSessionPath 'Fixture' -ExpectedSettingsFingerprint ('a'*64) | Should -BeTrue
        Should -Invoke Restore-Session -Exactly 1 -ParameterFilter {$SessionPath -ceq 'ResolvedFixture' -and $NoReboot -and $ExpectedSettingsFingerprint -ceq ('a'*64)}
    }
    It 'keeps existing restore calls free of an invented settings fingerprint' {
        & $script:CliRestoreTransport -RestoreSessionPath 'Fixture' | Should -BeTrue
        Should -Invoke Restore-Session -Exactly 1 -ParameterFilter {$SessionPath -ceq 'ResolvedFixture' -and $NoReboot -and -not $ExpectedSettingsFingerprint}
    }
    It 'rejects malformed fingerprints and Apply combinations before dispatch' {
        {& $script:CliRestoreTransport -RestoreSessionPath 'Fixture' -ExpectedSettingsFingerprint 'bad'} | Should -Throw
        {& $script:CliRestoreTransport -Module ASR -ExpectedSettingsFingerprint ('a'*64)} | Should -Throw
        Should -Invoke Restore-Session -Exactly 0
    }
}

Describe 'Interactive Xbox restore keeps the displayed settings comparison' {
    BeforeEach {
        $script:session=[pscustomobject]@{
            Restorable=$true;SessionId='XboxFixture';Timestamp='2026-10-01';FolderPath='XboxFixture';TotalItems=18
            RestoreMode='SettingsOnly';ExpectedSettingsFingerprint=('a'*64)
            Modules=@([pscustomobject]@{name='SecurityBaseline';actionId='Xbox'})
        }
        $script:answers=[Collections.Generic.Queue[string]]::new()
        Mock Show-BackupList {$script:session}
        Mock Read-Host {if($script:answers.Count -eq 0){throw 'Unexpected module or reboot prompt'};$script:answers.Dequeue()}
        Mock Write-Host {}
        Mock Start-Sleep {}
        Mock Write-ColorText {}
        Mock Write-Step {}
        Mock Restore-Session {$true}
    }
    It 'shows the app boundary and passes the original displayed fingerprint after confirmation' {
        foreach($answer in @('1','Y')){$script:answers.Enqueue($answer)}
        Invoke-RestoreWorkflow
        Should -Invoke Restore-Session -Exactly 1 -ParameterFilter {
            $ExpectedSettingsFingerprint -ceq ('a'*64) -and $SessionPath -ceq 'XboxFixture' -and
            -not $ModuleNames -and $SuppressRebootPrompt
        }
        Should -Invoke Write-ColorText -Exactly 1 -ParameterFilter {$Text -like '*Installed apps and their data are left unchanged*'}
        Should -Invoke Write-Step -Exactly 1 -ParameterFilter {$Status -ceq 'SUCCESS'}
        $script:answers.Count | Should -Be 0
    }
    It 'does not restore when the settings fingerprint is unavailable' {
        $script:session.ExpectedSettingsFingerprint=''
        $script:answers.Enqueue('1')
        Invoke-RestoreWorkflow
        Should -Invoke Restore-Session -Exactly 0
        Should -Invoke Write-Step -Exactly 1 -ParameterFilter {$Status -ceq 'ERROR'}
    }
    It 'does not restore after the user cancels' {
        foreach($answer in @('1','N')){$script:answers.Enqueue($answer)}
        Invoke-RestoreWorkflow
        Should -Invoke Restore-Session -Exactly 0
    }
    It 'retains a stale-comparison failure without claiming successful recovery' {
        Mock Restore-Session {throw 'Xbox settings changed after recovery was displayed'}
        foreach($answer in @('1','Y')){$script:answers.Enqueue($answer)}
        Invoke-RestoreWorkflow
        Should -Invoke Restore-Session -Exactly 1
        Should -Invoke Write-Step -Exactly 0 -ParameterFilter {$Status -ceq 'SUCCESS'}
        Should -Invoke Write-Step -Exactly 1 -ParameterFilter {$Status -ceq 'ERROR' -and $Text -like '*changed after recovery was displayed*'}
    }
}

Describe 'Interactive restore selection preserves the complete user choice' {
    BeforeEach {
        $script:answers = [System.Collections.Generic.Queue[string]]::new()
        Mock Read-Host {
            if ($script:answers.Count -eq 0) { throw 'Unexpected extra prompt' }
            $script:answers.Dequeue()
        }
        Mock Write-Host { }
        Mock Start-Sleep { }
        Mock Restore-Session { $false }
    }

    It 'rejects the complete mixed selection <InputText> before accepting a correction' -TestCases @(
        @{InputText='1,junk'}
        @{InputText='1,4'}
        @{InputText='1,2147483648'}
        @{InputText='1,0'}
    ) {
        param($InputText)
        foreach ($answer in @('1', 'M', $InputText, '2', 'Y')) { $script:answers.Enqueue($answer) }
        Invoke-RestoreWorkflow
        Should -Invoke Restore-Session -Exactly -Times 1
        Should -Invoke Restore-Session -Exactly -Times 1 -ParameterFilter {
            $SessionPath -eq 'SelectionFixture' -and
            @($ModuleNames).Count -eq 1 -and $ModuleNames[0] -ceq 'DNS' -and
            $SuppressRebootPrompt
        }
        $script:answers.Count | Should -Be 0
    }

    It 'keeps supported separators and duplicate selections' {
        foreach ($answer in @('1', 'M', '3,1;3 2', 'Y')) { $script:answers.Enqueue($answer) }
        Invoke-RestoreWorkflow
        Should -Invoke Restore-Session -Exactly -Times 1 -ParameterFilter {
            ($ModuleNames -join ',') -ceq 'ASR,DNS,AntiAI'
        }
        $script:answers.Count | Should -Be 0
    }

    It 'allows cancellation after an invalid mixed selection without restoring anything' {
        foreach ($answer in @('1', 'M', '1,junk', '0')) { $script:answers.Enqueue($answer) }
        { Invoke-RestoreWorkflow } | Should -Not -Throw
        Should -Invoke Restore-Session -Exactly -Times 0
        $script:answers.Count | Should -Be 0
    }
}
