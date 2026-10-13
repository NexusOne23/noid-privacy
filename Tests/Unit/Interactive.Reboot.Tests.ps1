#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    foreach ($source in @(
        @{File='NoIDPrivacy.ps1'; Function='Test-NoIDApplyRebootRequired'},
        @{File='NoIDPrivacy-Interactive.ps1'; Function='Invoke-HardeningWorkflow'}
    )) {
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $repo $source.File), [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw 'Reboot contract source must parse' }
        if ($source.File -eq 'NoIDPrivacy.ps1') {
            $assignment = $ast.Find({ param($n)
                $n -is [Management.Automation.Language.AssignmentStatementAst] -and
                $n.Left.Extent.Text -ceq '$guiResult'
            }, $true)
            if ($null -eq $assignment) { throw 'GUI result producer is missing' }
            $script:guiResultProducer = [scriptblock]::Create($assignment.Right.Extent.Text)
        }
        $name = $source.Function
        $function = @($ast.FindAll({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name
        }, $true))
        if ($function.Count -ne 1) { throw "Expected one $name function" }
        # Preserve a real script root for the menu's sibling engine lookup.
        $fixturePath = Join-Path $TestDrive ($source.Function + '.ps1')
        Set-Content -LiteralPath $fixturePath -Value $function[0].Extent.Text -Encoding UTF8
        . $fixturePath
    }
    function Write-Banner {}
    function Write-Header { param($Text) $null = $Text }
    function Write-Step { param($Text, $Status) $null = $Text, $Status }
    function Write-ColorText { param($Text, $Color, [switch]$NoNewline) $null = $Text, $Color, $NoNewline }
    function Invoke-RebootPrompt { param([switch]$HadFailures) $null = $HadFailures; throw 'Reboot prompt must be mocked' }
}

Describe 'Restart need remains independent of aggregate success' {
    It 'retains a restart-sensitive result even when another module failed' {
        $results = @(
            [pscustomobject]@{Success=$true;RequiresReboot=$true},
            [pscustomobject]@{Success=$false;Errors=@('fixture failure')}
        )
        Test-NoIDApplyRebootRequired -ModuleResults $results | Should -BeTrue
        Test-NoIDApplyRebootRequired -ModuleResults $results -DryRun | Should -BeFalse
    }

    It 'also retains changes made before the same module failed' {
        Test-NoIDApplyRebootRequired -ModuleResults @(
            [pscustomobject]@{Success=$false;RebootRequired=$true}
        ) | Should -BeTrue
    }

    It 'does not infer a restart from success, module names, or string values' {
        Test-NoIDApplyRebootRequired -ModuleResults @(
            [pscustomobject]@{ModuleName='SecurityBaseline';Success=$true},
            [pscustomobject]@{ModuleName='ASR';Success=$true},
            [pscustomobject]@{RequiresReboot=$false;RebootRequired='false'}
        ) | Should -BeFalse
        Test-NoIDApplyRebootRequired -ModuleResults @() | Should -BeFalse
    }
}

Describe 'GUI result preserves restart need without changing the outcome' {
    It 'transports success=<Success>, restart=<Restart>, preview=<Preview>' -TestCases @(
        @{Success=$true;Restart=$true;Preview=$false},
        @{Success=$true;Restart=$false;Preview=$false},
        @{Success=$false;Restart=$true;Preview=$false},
        @{Success=$false;Restart=$false;Preview=$false},
        @{Success=$false;Restart=$true;Preview=$true}
    ) {
        param($Success, $Restart, $Preview)
        $script:ConfigPayloadSha256 = 'a' * 64
        $result = [pscustomobject]@{
            Success=$Success;Status=$(if($Success){'Success'}else{'Failed'})
            TotalSettingsApplied=1;ModulesExecuted=1;ModulesSkipped=0
            ModulesFailed=$(if($Success){0}else{1});BackupPath='C:\Backups\Fixture'
            ModuleResults=@([pscustomobject]@{
                ModuleName='SecurityBaseline';Success=$Success
                Status=$(if($Success){'Success'}else{'Failed'})
                AppliedSettingsCount=1;RequiresReboot=$Restart
            })
        }
        $needsReboot = Test-NoIDApplyRebootRequired -ModuleResults $result.ModuleResults -DryRun:$Preview
        $null = $needsReboot # Consumed by the production assignment in the caller scope.
        $json = & $script:guiResultProducer | ConvertTo-Json -Depth 5 | ConvertFrom-Json
        $json.schemaVersion | Should -Be 3
        $json.requiresReboot | Should -BeOfType ([bool])
        $json.requiresReboot | Should -Be ($Restart -and -not $Preview)
        $json.success | Should -Be $Success
        $json.modules[0].success | Should -Be $Success
        $json.totalSettingsApplied | Should -Be 1
    }
}

Describe 'Interactive apply restart prompt' {
    BeforeEach {
        $script:engineFixture = Join-Path $TestDrive 'NoIDPrivacy.ps1'
        @'
param($Module, $Modules, [switch]$VerboseLogging, [ref]$RebootRequired)
$RebootRequired.Value = $global:NoIDTestRestartNeeded
exit $global:NoIDTestApplyExitCode
'@ | Set-Content -LiteralPath $script:engineFixture -Encoding UTF8
        Mock Write-Host {}
        Mock Invoke-RebootPrompt {}
    }

    AfterEach {
        Remove-Variable NoIDTestRestartNeeded,NoIDTestApplyExitCode -Scope Global -ErrorAction SilentlyContinue
    }

    It 'preserves partial failure and restart need for <Selection>' -TestCases @(
        @{Selection='single'; Modules=@('AdvancedSecurity')},
        @{Selection='multiple'; Modules=@('SecurityBaseline','Privacy')},
        @{Selection='all'; Modules=@('SecurityBaseline','ASR','DNS','Privacy','AntiAI','EdgeHardening','AdvancedSecurity')}
    ) {
        param($Selection, $Modules)
        $null = $Selection
        $global:NoIDTestRestartNeeded = $true
        $global:NoIDTestApplyExitCode = 4
        Invoke-HardeningWorkflow -SelectedModules $Modules
        Should -Invoke Invoke-RebootPrompt -Exactly -Times 1 -ParameterFilter { $HadFailures }
    }

    It 'does not prompt after a successful ASR-only run without restart-sensitive changes' {
        $global:NoIDTestRestartNeeded = $false
        $global:NoIDTestApplyExitCode = 0
        Invoke-HardeningWorkflow -SelectedModules @('ASR')
        Should -Invoke Invoke-RebootPrompt -Exactly -Times 0
    }

    It 'prompts without an error notice after a successful restart-sensitive run' {
        $global:NoIDTestRestartNeeded = $true
        $global:NoIDTestApplyExitCode = 10
        Invoke-HardeningWorkflow -SelectedModules @('SecurityBaseline')
        Should -Invoke Invoke-RebootPrompt -Exactly -Times 1 -ParameterFilter { -not $HadFailures }
    }
}

Describe 'SecurityBaseline finalization keeps applied restart information' {
    BeforeAll {
        $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $path = Join-Path $repo 'Modules/SecurityBaseline/Public/Invoke-SecurityBaseline.ps1'
        $script:baselineSourceDirectory = Split-Path $path -Parent
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw 'Baseline source must parse' }
        $function = $ast.Find({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-SecurityBaseline'
        }, $true)
        $initializer = $function.Body.BeginBlock.Find({ param($n)
            $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$result'
        }, $true)
        $script:baselineResultInitializer = [scriptblock]::Create($initializer.Right.Extent.Text)
        $body = ($function.Body.EndBlock.Statements.Extent.Text -join "`n").Replace('$PSScriptRoot', '$script:baselineSourceDirectory')
        $script:baselineFinalizer = [scriptblock]::Create($body)
        function Write-ModuleLog { param($Level, $Message, $Module) $null = $Level, $Message, $Module }
        function Write-Log {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Test placeholder for the engine logger.')]
            [CmdletBinding()] param($Level, $Message, $Module) $null = $Level, $Message, $Module
        }
    }

    It 'reports restart=<Expected> for applied=<Applied>, preview=<Preview>, metadata failure=<MetadataFailure>' -TestCases @(
        @{Applied=1;Preview=$false;MetadataFailure=$false;Expected=$true},
        @{Applied=1;Preview=$false;MetadataFailure=$true;Expected=$true},
        @{Applied=0;Preview=$false;MetadataFailure=$false;Expected=$false},
        @{Applied=1;Preview=$true;MetadataFailure=$false;Expected=$false}
    ) {
        param($Applied, $Preview, $MetadataFailure, $Expected)
        $moduleName='SecurityBaseline'; $startTime=Get-Date
        $tempComputerRegPath=$null; $tempSecurityTemplatePath=$null
        $DryRun=[switch]$Preview
        # The extracted production finalizer consumes these caller-scope values.
        $null = $moduleName, $startTime, $tempComputerRegPath, $tempSecurityTemplatePath, $DryRun
        $result=& $script:baselineResultInitializer
        $result.Success=$false
        $result.SettingsApplied=$Applied
        $result.Errors=@('fixture later apply failure')
        if ($MetadataFailure) { Mock Get-Content { throw 'fixture metadata failure' } }
        $actual=& $script:baselineFinalizer
        $actual.Success | Should -BeFalse
        $actual.RequiresReboot | Should -Be $Expected
        if ($MetadataFailure) { $actual.Errors -join '|' | Should -Match 'fixture metadata failure' }
    }
}
