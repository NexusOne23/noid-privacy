#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/ASR/Public/Invoke-ASRRules.ps1')
    . (Join-Path $repo 'Modules/ASR/Private/Get-ASRApplicabilityPlan.ps1')
    $script:TerminalRules = Get-Content (Join-Path $repo 'Modules/ASR/Config/ASR-Rules.json') -Raw | ConvertFrom-Json
    foreach ($rule in $script:TerminalRules) {
        if (-not $rule.PSObject.Properties['WindowsClientApplicable']) {
            $rule | Add-Member -NotePropertyName WindowsClientApplicable -NotePropertyValue $true
        }
    }
    function Initialize-BackupSystem { throw 'Unexpected backup call' }
    Set-Item -Path Function:Write-Log -Value { param($Level, $Message, $Module, $Exception); $null = $Level, $Message, $Module, $Exception }
    function Test-IsAdmin { return $true }
    function Test-WindowsVersion { param($MinimumBuild) $null = $MinimumBuild; return $true }
    function Test-ThirdPartySecurityProduct { return [pscustomobject]@{Detected=$false;ProductName=$null} }
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        Set-Item -Path Function:Get-MpComputerStatus -Value {
            throw 'The Defender status query must be mocked'
        }
    }
    Set-Item -Path Function:Get-Service -Value { param($Name) $null = $Name; return [pscustomobject]@{Status='Running'} }
    function Get-ASRRuleDefinitions { return $script:TerminalRules }
    function Test-ConfigMgrPresence { return $false }
    function Test-CloudProtection { return $true }
    function Test-NonInteractiveMode { return $true }
    function Get-NonInteractiveValue { param($Module, $Key, [switch]$Required) $null = $Module, $Key, $Required; return $false }
    function Write-NonInteractiveDecision { param($Module, $Decision, $Value) $null = $Module, $Decision, $Value }
    Set-Item -Path Function:Set-ASRViaPowerShell -Value { param($Rules, [switch]$DryRun) $null = $DryRun; return @{Applied=$Rules.Count;Errors=@();Warnings=@()} }
}

Describe 'ASR terminal results and pre-backup refusals' {
    BeforeEach {
        Mock Write-Log {}
        Mock Initialize-BackupSystem { throw 'DryRun reached backup initialization' }
        Mock Get-ASRRuleDefinitions {
            # Every run gets distinct mutable rule objects, as the product loader does.
            $script:TerminalRules | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        }
        Mock Test-IsAdmin { return $true }
        Mock Test-CloudProtection { return $true }
        Mock Get-MpComputerStatus { [pscustomobject]@{AMRunningMode='Normal';AntivirusEnabled=$true;RealTimeProtectionEnabled=$true} }
        Mock Set-ASRViaPowerShell { param($Rules) @{Applied=$Rules.Count;Errors=@();Warnings=@()} }
        Mock Get-NonInteractiveValue { return $false }
    }

    It 'returns a terminal failure after a prerequisite refusal' {
        Mock Test-IsAdmin { return $false }
        $result = Invoke-ASRRules -DryRun
        $result.Success | Should -BeFalse
        $result.Status | Should -BeExactly 'Failed'
        $result.RulesPreviewed | Should -Be 0
        $result.Errors | Should -Contain 'Administrator privileges required'
    }

    It 'does not log an aborted preview as completed' {
        Mock Test-IsAdmin { return $false }
        $null = Invoke-ASRRules -DryRun
        Should -Invoke Write-Log -Times 0 -Exactly -ParameterFilter { $Message -like 'DryRun preview completed*' }
    }

    It 'refuses unavailable cloud protection before producing a plan or backup' {
        Mock Test-CloudProtection { return $false }
        $result = Invoke-ASRRules -DryRun
        $result.Success | Should -BeFalse
        $result.Status | Should -BeExactly 'Failed'
        $result.Errors | Should -Contain 'ASR application cancelled (cloud protection required, continueWithoutCloud=false)'
        @($result.Details.RequestedActions).Count | Should -Be 0
        $result.BackupCreated | Should -BeFalse
        Should -Invoke Initialize-BackupSystem -Times 0 -Exactly
        Should -Invoke Set-ASRViaPowerShell -Times 0 -Exactly
    }

    It 'previews the selected rules when continuing without cloud is explicitly chosen' {
        Mock Test-CloudProtection { return $false }
        Mock Get-NonInteractiveValue { param($Key) return $Key -ceq 'continueWithoutCloud' }
        $result = Invoke-ASRRules -DryRun
        $result.Success | Should -BeTrue
        $result.Status | Should -BeExactly 'DryRun'
        $result.RulesPreviewed | Should -Be 18
        @($result.Details.RequestedActions).Count | Should -Be 18
        $result.BackupCreated | Should -BeFalse
        Should -Invoke Initialize-BackupSystem -Times 0 -Exactly
    }

    It 'returns a terminal failure when target preview fails' {
        Mock Set-ASRViaPowerShell { @{Applied=0;Errors=@('preview fixture failure');Warnings=@()} }
        $result = Invoke-ASRRules -DryRun
        $result.Success | Should -BeFalse
        $result.Status | Should -BeExactly 'Failed'
        $result.Errors | Should -Contain 'preview fixture failure'
    }

    It 'replaces a prior success status when final metadata validation fails' {
        Mock Get-Content { throw 'count fixture failure' } -ParameterFilter { $LiteralPath -like '*SettingsCounts.json' }
        $result = Invoke-ASRRules -DryRun
        $result.Success | Should -BeFalse
        $result.Status | Should -BeExactly 'Failed'
    }

    It 'retains the deliberate skipped status when Defender is not primary' {
        Mock Get-MpComputerStatus { [pscustomobject]@{AMRunningMode='Passive';AntivirusEnabled=$true;RealTimeProtectionEnabled=$true} }
        $result = Invoke-ASRRules -DryRun
        $result.Success | Should -BeFalse
        $result.Status | Should -BeExactly 'Skipped'
        $result.RulesSkipped | Should -Be 18
        @($result.Errors).Count | Should -Be 0
        Should -Invoke Initialize-BackupSystem -Times 0 -Exactly
    }

    It 'reports the actual PSExec/WMI mode for <Case>' -ForEach @(
        @{ Case='declared management tools'; UsesTools=$true; Detected=$false; Override=$false; ExpectedAction=2; ExpectedMode='AUDIT' },
        @{ Case='detected Configuration Manager'; UsesTools=$false; Detected=$true; Override=$false; ExpectedAction=2; ExpectedMode='AUDIT' },
        @{ Case='explicit override of declared tools'; UsesTools=$true; Detected=$false; Override=$true; ExpectedAction=1; ExpectedMode='BLOCK' },
        @{ Case='explicit override of detected tools'; UsesTools=$false; Detected=$true; Override=$true; ExpectedAction=1; ExpectedMode='BLOCK' }
    ) {
        $script:reportingUsesTools = $UsesTools
        $script:reportingDetected = $Detected
        $script:managementDecision = $null
        Mock Test-ConfigMgrPresence { $script:reportingDetected }
        Mock Get-NonInteractiveValue {
            param($Key)
            if ($Key -ceq 'usesManagementTools') { return $script:reportingUsesTools }
            return $false
        }
        Mock Write-NonInteractiveDecision {
            param($Value)
            $script:managementDecision = $Value
        } -ParameterFilter { $Decision -ceq 'Management tools rule' }

        $result = Invoke-ASRRules -DryRun -AllowPSExecWMI:$Override

        $result.Success | Should -BeTrue
        $rule = @($result.Details.RequestedActions | Where-Object Guid -eq 'd1e49aac-8f56-4280-b9ba-993a6d77406c')
        $rule.Count | Should -Be 1
        $rule[0].Action | Should -Be $ExpectedAction
        $script:managementDecision | Should -Match ('^' + $ExpectedMode + '\b')
        Should -Invoke Initialize-BackupSystem -Times 0 -Exactly
    }
}
