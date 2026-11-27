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
    # The block that decides which action each rule is expected to have.
    $planBlocks = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -ceq "Test-VerificationModuleSelected 'ASR'" -and
        $node.Extent.Text -match "Source = 'AssessmentProfile'"
    }, $true))
    if ($planBlocks.Count -ne 1) { throw 'Expected one production ASR expectation block' }
    $script:AsrExpectation = [scriptblock]::Create($planBlocks[0].Extent.Text)
    Set-Item -Path function:Write-Log -Value { param($Level, $Message, $Module); $null = $Level, $Message, $Module }
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
        # Nothing was measured, so nothing passes and nothing counts as a
        # measured difference: the eighteen applicable rules are not proven.
        $category = $results.AllSettings[0]
        $category.Passed | Should -Be 0
        $category.Failed | Should -Be 0
        $category.NotChecked | Should -Be 18
        $category.NotCheckedCannotVerify | Should -Be 18
        $category.NotCheckedDeliberate | Should -Be 0
        $category.NotApplicable | Should -Be 1
        @($category.NotCheckedDetails).Count | Should -Be 1
        $category.NotCheckedDetails[0].VerificationReasonCode | Should -BeExactly 'ASR.NotExecutable'
        $category.NotCheckedDetails[0].AffectedTargetCount | Should -Be 18
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

Describe 'Check before hardening: the expected ASR action is the one an Apply of the profile would set' {
    BeforeEach {
        $rootPath = $script:VerifierRepo
        $asrConfigPath = Join-Path $rootPath 'Modules/ASR/Config'
        $EXPECTED_ASR_COUNT = 19
        $appliedScopeRun = $true
        $assessmentRun = $true
        $AppliedSessionPath = ''
        $asrIntent = $null
        $frameworkConfig = [pscustomobject]@{ modules = [pscustomobject]@{ ASR = [pscustomobject]@{
                    usesManagementTools = $false; allowNewSoftware = $false } } }
        $sealedAppliedAsrPlan = $null
        # These variables are consumed in the extracted production block's scope.
        $null = $asrConfigPath, $EXPECTED_ASR_COUNT, $appliedScopeRun, $assessmentRun, $AppliedSessionPath, $asrIntent, $frameworkConfig, $sealedAppliedAsrPlan
        $script:ManagementRule = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        $script:PrevalenceRule = '01443614-cd74-433a-b99e-2ecdc07bfc25'
        Mock Get-Service { @() }
        Mock Get-Process { @() }
    }

    It 'keeps Block for both choice rules when the profile asks for it and no management client is installed' {
        . $script:AsrExpectation
        $sealedAppliedAsrPlan.Source | Should -BeExactly 'AssessmentProfile'
        $sealedAppliedAsrPlan.ActionMap.Count | Should -Be 18
        $sealedAppliedAsrPlan.ActionMap[$script:ManagementRule] | Should -Be 1
        $sealedAppliedAsrPlan.ActionMap[$script:PrevalenceRule] | Should -Be 1
        @($sealedAppliedAsrPlan.ActionMap.Values | Where-Object { $_ -ne 1 }).Count | Should -Be 0
    }

    It 'expects Audit for the two choice rules the profile relaxes' {
        $frameworkConfig.modules.ASR.usesManagementTools = $true
        $frameworkConfig.modules.ASR.allowNewSoftware = $true
        . $script:AsrExpectation
        $sealedAppliedAsrPlan.ActionMap[$script:ManagementRule] | Should -Be 2
        $sealedAppliedAsrPlan.ActionMap[$script:PrevalenceRule] | Should -Be 2
        @($sealedAppliedAsrPlan.ActionMap.Values | Where-Object { $_ -eq 2 }).Count | Should -Be 2
    }

    It 'expects Audit for PSExec/WMI on a PC with <Evidence>, as the Apply would set it' -TestCases @(
        @{ Evidence = 'an installed Configuration Manager service' }, @{ Evidence = 'a running Configuration Manager process' }
    ) {
        param($Evidence)
        if ($Evidence -like '*service*') { Mock Get-Service { [pscustomobject]@{ Name = 'CcmExec'; Status = 'Stopped' } } }
        else { Mock Get-Process { [pscustomobject]@{ ProcessName = 'CcmExec' } } }
        . $script:AsrExpectation
        $sealedAppliedAsrPlan.ActionMap[$script:ManagementRule] | Should -Be 2
        # The detection concerns the management rule only.
        $sealedAppliedAsrPlan.ActionMap[$script:PrevalenceRule] | Should -Be 1
    }

    It 'lets the profile choice stand alone when the management client cannot be inspected' {
        Mock Get-Service { throw 'service control manager unavailable' }
        . $script:AsrExpectation
        $sealedAppliedAsrPlan.ActionMap[$script:ManagementRule] | Should -Be 1
    }

    It 'refuses a profile without the Boolean choice <Choice>' -TestCases @(
        @{ Choice = 'usesManagementTools' }, @{ Choice = 'allowNewSoftware' }
    ) {
        param($Choice)
        $frameworkConfig.modules.ASR.$Choice = 'yes'
        { . $script:AsrExpectation } | Should -Throw "*requires the Boolean ASR profile choice: $Choice*"
    }
}

Describe 'Standalone verification: saved ASR choices' {
    BeforeEach {
        $rootPath = $script:VerifierRepo
        $asrConfigPath = Join-Path $rootPath 'Modules/ASR/Config'
        $EXPECTED_ASR_COUNT = 19
        $appliedScopeRun = $false
        $assessmentRun = $false
        $AppliedSessionPath = ''
        $frameworkConfig = $null
        $sealedAppliedAsrPlan = $null
        $declaredRules = Get-Content (Join-Path $asrConfigPath 'ASR-Rules.json') -Raw | ConvertFrom-Json
        $script:SavedActions = @($declaredRules |
                Where-Object { $_.WindowsClientApplicable -ne $false } |
                ForEach-Object { [pscustomobject]@{ Guid = [string]$_.GUID; Action = 1 } })
        $asrIntent = [pscustomobject]@{ requestedActions = $script:SavedActions }
        # These variables are consumed in the extracted production block's scope.
        $null = $EXPECTED_ASR_COUNT, $appliedScopeRun, $assessmentRun, $AppliedSessionPath, $asrIntent, $frameworkConfig, $sealedAppliedAsrPlan
        Mock Write-Host {}
    }

    It 'uses choices that cover exactly the applicable rules of this version' {
        $asrIntent.requestedActions[0].Action = 2
        . $script:AsrExpectation
        $sealedAppliedAsrPlan.Source | Should -BeExactly 'DurableApplyIntent'
        $sealedAppliedAsrPlan.ActionMap.Count | Should -Be 18
        @($sealedAppliedAsrPlan.ActionMap.Values | Where-Object { $_ -eq 2 }).Count | Should -Be 1
    }

    It 'sets aside choices that <Case> instead of ending the run without a report' -TestCases @(
        @{ Case = 'lack a rule this version declares'; Fault = 'Missing' }
        @{ Case = 'name a rule this version does not declare'; Fault = 'Extra' }
        @{ Case = 'name a rule twice'; Fault = 'Duplicate' }
        @{ Case = 'carry an unsupported action'; Fault = 'Action' }
        @{ Case = 'carry an unreadable rule ID'; Fault = 'Guid' }
    ) {
        param($Case, $Fault)
        $null = $Case
        switch ($Fault) {
            'Missing' { $asrIntent.requestedActions = @($script:SavedActions | Select-Object -Skip 1) }
            'Extra' { $asrIntent.requestedActions = @($script:SavedActions) + [pscustomobject]@{ Guid = '11111111-2222-3333-4444-555555555555'; Action = 1 } }
            'Duplicate' { $asrIntent.requestedActions = @($script:SavedActions) + $script:SavedActions[0] }
            'Action' { $asrIntent.requestedActions[0].Action = 5 }
            'Guid' { $asrIntent.requestedActions[0].Guid = 'not-a-guid' }
        }

        { . $script:AsrExpectation } | Should -Not -Throw
        . $script:AsrExpectation
        $sealedAppliedAsrPlan | Should -BeNullOrEmpty
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'Saved ASR choices do not fit the rule list of this version*' }
    }
}
