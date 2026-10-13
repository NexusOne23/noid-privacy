#Requires -Version 5.1

BeforeAll {
    $script:VerifierRepo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $script:VerifierRepo 'Tools/Verify-Complete-Hardening.ps1'), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Verifier does not parse' }
    $blocks = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -ceq "Test-VerificationModuleSelected 'ASR'" -and
        $node.Extent.Text -match 'Verifying ASR Rules'
    }, $true))
    if ($blocks.Count -ne 1) { throw 'Expected one production ASR verification block' }
    $script:AsrVerification = [scriptblock]::Create($blocks[0].Extent.Text)
    . (Join-Path $script:VerifierRepo 'Tools/Private/Get-VerificationModulePresentation.ps1')
    . (Join-Path $script:VerifierRepo 'Tools/Private/New-HardeningHtmlReport.ps1')
    . (Join-Path $script:VerifierRepo 'Core/AsrPolicyRuntime.ps1')
    function Test-VerificationModuleSelected { param($Name) $null = $Name; return $true }
    function Write-VerificationStep { param($Message) $null = $Message }
    function Test-IsMicrosoftDefenderSecurityCenterProduct { param($Product) $null = $Product; return $true }
}

Describe 'Real ASR verifier cloud evidence and HTML result' {
    BeforeEach {
        $rootPath = $script:VerifierRepo
        $EXPECTED_ASR_COUNT = 19
        $declaredAsrRules = Get-Content (Join-Path $rootPath 'Modules/ASR/Config/ASR-Rules.json') -Raw | ConvertFrom-Json
        $applicable = @($declaredAsrRules | Where-Object { $_.WindowsClientApplicable -ne $false })
        $map = @{}; foreach ($rule in $applicable) { $map[[string]$rule.GUID] = [int]$rule.Action }
        $sealedAppliedAsrPlan = [pscustomobject]@{ActionMap=$map}
        $script:CloudPreference = [pscustomobject]@{
            MAPSReporting=2
            AttackSurfaceReductionRules_Ids=@($applicable.GUID)
            AttackSurfaceReductionRules_Actions=@($applicable.Action)
        }
        $results = [pscustomobject]@{
            ASRRules=19; Verified=0; Failed=0; NotChecked=0; AllSettings=@(); FailedSettings=@()
        }
        # These variables are consumed in the extracted production block's scope.
        $null = $EXPECTED_ASR_COUNT, $sealedAppliedAsrPlan, $results
        Mock Get-CimInstance { @() }
        Mock Get-MpComputerStatus { [pscustomobject]@{AMRunningMode='Normal';AntivirusEnabled=$true;RealTimeProtectionEnabled=$true} }
        Mock Get-MpPreference { $script:CloudPreference }
        Mock Read-NoIDAsrRuntimeRecord { $null }
        Mock Write-Host {}
    }

    It 'does not report configured rules as passing while runtime recovery is pending' {
        Mock Read-NoIDAsrRuntimeRecord { [pscustomobject]@{Target='AsrPolicyRuntime'} }
        . $script:AsrVerification
        $results.AllSettings[0].Passed | Should -Be 0
        $results.AllSettings[0].Failed | Should -Be 18
        $results.AllSettings[0].NotApplicable | Should -Be 1
    }

    It 'passes all eighteen applicable rules with documented MAPS membership <Membership>' -TestCases @(@{Membership=1},@{Membership=2}) {
        param($Membership)
        $script:CloudPreference.MAPSReporting = $Membership
        . $script:AsrVerification
        $results.AllSettings.Count | Should -Be 1
        $results.AllSettings[0].Passed | Should -Be 18
        $results.AllSettings[0].Failed | Should -Be 0
        $results.AllSettings[0].NotChecked | Should -Be 0
        $results.AllSettings[0].NotApplicable | Should -Be 1
    }

    It 'keeps three cloud-dependent rules unproven for <Label>' -TestCases @(
        @{Label='disabled';Value=0}, @{Label='null';Value=$null}, @{Label='unknown numeric value';Value=3},
        @{Label='string';Value='2'}, @{Label='boolean';Value=$true}, @{Label='fraction';Value=1.5}
    ) {
        param($Label,$Value)
        $null = $Label
        $script:CloudPreference.MAPSReporting = $Value
        . $script:AsrVerification
        $category = $results.AllSettings[0]
        $category.Passed | Should -Be 15
        $category.Failed | Should -Be 0
        $category.NotChecked | Should -Be 3
        $category.NotCheckedDeliberate | Should -Be 0
        $category.NotCheckedCannotVerify | Should -Be 3
        $category.NotApplicable | Should -Be 1
        @($category.NotCheckedDetails | Where-Object VerificationReasonCode -eq 'ASR.CloudProtectionUnavailable').Count | Should -Be 3
    }

    It 'does not mistake a missing MAPS property for enabled cloud protection' {
        $script:CloudPreference.PSObject.Properties.Remove('MAPSReporting')
        . $script:AsrVerification
        $results.AllSettings[0].NotCheckedCannotVerify | Should -Be 3
    }

    It 'retains a measured mismatch instead of hiding it behind cloud uncertainty' {
        $script:CloudPreference.MAPSReporting = 0
        $index = [Array]::IndexOf($script:CloudPreference.AttackSurfaceReductionRules_Ids, '01443614-cd74-433a-b99e-2ecdc07bfc25')
        $index | Should -BeGreaterOrEqual 0
        $script:CloudPreference.AttackSurfaceReductionRules_Actions[$index] = 0
        . $script:AsrVerification
        $results.AllSettings[0].Passed | Should -Be 15
        $results.AllSettings[0].Failed | Should -Be 1
        $results.AllSettings[0].NotCheckedCannotVerify | Should -Be 2
    }

    It 'never passes a configured rule when Defender is passive' {
        Mock Get-MpComputerStatus { [pscustomobject]@{AMRunningMode='Passive';AntivirusEnabled=$true;RealTimeProtectionEnabled=$false} }
        Mock Get-Service { @() }
        . $script:AsrVerification
        $results.AllSettings[0].Passed | Should -Be 0
        $results.AllSettings[0].NotCheckedCannotVerify | Should -Be 18
    }

    It 'renders the actual missing-cloud result below 100 percent with three unproven failures' {
        $script:CloudPreference.MAPSReporting = 0
        . $script:AsrVerification
        $category = $results.AllSettings[0]
        $report = [pscustomobject]@{
            SelectedModules=@('ASR'); AppliedScopeRun=$true; TotalSettings=19; ProductTargetInventory=19
            Verified=$category.Passed; Failed=$category.Failed; NotChecked=$category.NotChecked
            NotCheckedDeliberate=0; NotCheckedNoSavedChoice=0; NotCheckedCannotVerify=3; NotApplicable=1
            AllSettings=@($category); IntentReference='Test fixture'; PrivacyMode=$null
        }
        Mock Get-CimInstance { [pscustomobject]@{Caption='Windows test fixture';BuildNumber='26300'} }
        $output = Join-Path $TestDrive 'asr-cloud.html'
        New-HardeningHtmlReport -Results $report -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw
        $html | Should -Match '83\.3% of 18 required checks passed &middot; 3 failed \(not proven\)'
        $html | Should -Match 'required cloud protection is disabled or not proven'
        $html | Should -Not -Match '100% of 18 required checks passed'
    }
}
