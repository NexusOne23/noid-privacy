#Requires -Version 5.1
BeforeAll {
    $script:FrameworkRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $tokens=$null; $errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $script:FrameworkRoot 'Core/Framework.ps1'),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Framework parse failed' }
    foreach ($name in @('Invoke-Hardening','New-NoIDFailedModuleRecord')) {
        $function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true)
        . ([scriptblock]::Create($function.Extent.Text))
    }
    . (Join-Path $script:FrameworkRoot 'Core/Readiness.ps1')
    function Get-LogLevelCount { param($Level) $null=$Level; 0 }
    function Get-LogWarningMessages { @() }
    function Write-Log {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Test placeholder for the engine logger.')]
        [CmdletBinding()] param($Level,$Message,$Module) $null=$Level,$Message,$Module
    }
    function Write-ErrorLog { param($Message,$Module,$ErrorRecord) $null=$Message,$Module,$ErrorRecord }
    function Test-NonInteractiveMode { $true }
    function Test-NoIDPlainConsole { $true }
    function Initialize-BackupSystem { throw 'Unexpected real backup' }
    function Set-SessionType {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',Justification='Read-only test placeholder.')]
        [CmdletBinding()] param($SessionType) $null=$SessionType
    }
    function Update-SessionDisplayName {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',Justification='Read-only test placeholder.')]
        [CmdletBinding()] param()
    }
    function Write-NoIDApplyIntentState { param($ModuleResults,$SessionPath) $null=$ModuleResults,$SessionPath }
    function Initialize-NoIDModuleDependencyBridge { param($ImportedModule) $null=$ImportedModule }
    function Invoke-SecurityBaseline { param([switch]$DryRun) $null=$DryRun; throw 'Unmocked baseline' }
    function Invoke-ASRRules { param([switch]$DryRun) $null=$DryRun; throw 'Unmocked ASR' }
    function Restore-NoIDPendingAsrRuntime {
        [CmdletBinding(SupportsShouldProcess)]param()
        $null = $PSCmdlet.ShouldProcess('fixture', 'Recover ASR runtime')
    }
}

Describe 'Unattended hardening prerequisite boundary' {
    BeforeEach {
        $script:NoIDMutationMutexName='Local\NoIDReadinessTest-'+[guid]::NewGuid().ToString('N')
        $script:Config=[pscustomobject]@{
            options=[pscustomobject]@{nonInteractive=$true;allowPartialHardening=$false}
            modules=[pscustomobject]@{
                SecurityBaseline=[pscustomobject]@{enabled=$true}
                ASR=[pscustomobject]@{enabled=$true;continueWithoutCloud=$false}
            }
        }
        $global:CurrentModule=''; $global:BackupBasePath=''
        Mock Get-NoIDASRReadiness { [pscustomobject]@{Defender='Active';CloudProtection='Enabled'} }
        Mock Initialize-BackupSystem { $global:BackupBasePath=$TestDrive; $true }
        Mock Get-Module { [pscustomobject]@{Name=$Name} }
        Mock Initialize-NoIDModuleDependencyBridge { }
        Mock Write-NoIDApplyIntentState { 'intent-fixture' }
        Mock Invoke-SecurityBaseline { [pscustomobject]@{ModuleName='SecurityBaseline';Success=$true;SettingsApplied=1} }
        Mock Invoke-ASRRules { [pscustomobject]@{ModuleName='ASR';Success=$true;RulesApplied=1;CoverageLimited=$false} }
    }
    AfterEach { $global:CurrentModule=''; $global:BackupBasePath='' }

    It 'blocks before backup or baseline writes when <Defender>/<Cloud> is not proven' -ForEach @(
        @{Defender='Unavailable';Cloud='Unknown'}, @{Defender='Unknown';Cloud='Unknown'},
        @{Defender='Active';Cloud='Disabled'}, @{Defender='Active';Cloud='Unknown'}
    ) {
        Mock Get-NoIDASRReadiness { [pscustomobject]@{Defender=$Defender;CloudProtection=$Cloud} }
        $r=Invoke-Hardening -Modules @('SecurityBaseline','ASR')
        $r.Success | Should -BeFalse
        $r.Status | Should -BeExactly 'PreflightBlocked'
        $r.ModulesExecuted | Should -Be 0
        $r.TotalSettingsApplied | Should -Be 0
        $r.BackupPath | Should -BeNullOrEmpty
        Should -Invoke Initialize-BackupSystem -Times 0 -Exactly
        Should -Invoke Invoke-SecurityBaseline -Times 0 -Exactly
        Should -Invoke Invoke-ASRRules -Times 0 -Exactly
        Should -Invoke Write-NoIDApplyIntentState -Times 0 -Exactly
    }

    It 'runs and records the other module only after an explicit partial choice' {
        $script:Config.options.allowPartialHardening=$true
        Mock Get-NoIDASRReadiness { [pscustomobject]@{Defender='Unavailable';CloudProtection='Unknown'} }
        $r=Invoke-Hardening -Modules @('SecurityBaseline','ASR')
        $r.Success | Should -BeFalse
        $r.Status | Should -BeExactly 'Partial'
        $r.ModulesExecuted | Should -Be 2
        $r.ModulesSkipped | Should -Be 1
        $r.ModulesFailed | Should -Be 0
        $r.ModuleResults[1].Status | Should -BeExactly 'Skipped'
        Should -Invoke Invoke-SecurityBaseline -Times 1 -Exactly
        Should -Invoke Invoke-ASRRules -Times 0 -Exactly
        Should -Invoke Write-NoIDApplyIntentState -Times 1 -Exactly -ParameterFilter {
            $ModuleResults[0].Success -and -not $ModuleResults[1].Success
        }
    }

    It 'retains ASR Apply intent but never reports full protection without cloud evidence' {
        $script:Config.modules.ASR.continueWithoutCloud=$true
        Mock Get-NoIDASRReadiness { [pscustomobject]@{Defender='Active';CloudProtection='Disabled'} }
        Mock Invoke-ASRRules { [pscustomobject]@{ModuleName='ASR';Success=$true;RulesApplied=1;CoverageLimited=$true} }
        $r=Invoke-Hardening -Module ASR
        $r.Success | Should -BeFalse
        $r.Status | Should -BeExactly 'Partial'
        $r.ModuleResults[0].Status | Should -BeExactly 'Limited'
        $r.ModulesFailed | Should -Be 0
        Should -Invoke Write-NoIDApplyIntentState -Times 1 -Exactly -ParameterFilter { $ModuleResults[0].Success }
    }

    It 'does not hide an intent-storage failure behind a partial status' {
        $script:Config.modules.ASR.continueWithoutCloud=$true
        Mock Invoke-ASRRules { [pscustomobject]@{ModuleName='ASR';Success=$true;RulesApplied=1;CoverageLimited=$true} }
        Mock Write-NoIDApplyIntentState { throw 'fixture intent failure' }
        $r=Invoke-Hardening -Module ASR
        $r.Status | Should -BeExactly 'Failed'
        ($r.Errors -join ';') | Should -Match 'fixture intent failure'
    }

    It 'keeps the full-success path when prerequisites and module results are proven' {
        $r=Invoke-Hardening -Modules @('SecurityBaseline','ASR')
        $r.Success | Should -BeTrue
        $r.Status | Should -BeExactly 'Success'
        Should -Invoke Invoke-SecurityBaseline -Times 1 -Exactly
        Should -Invoke Invoke-ASRRules -Times 1 -Exactly
    }
}
