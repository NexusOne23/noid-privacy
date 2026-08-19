#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $script:RepoRoot 'Tools/Private/Get-PrivacyVerificationPresentation.ps1')
    . (Join-Path $script:RepoRoot 'Tools/Private/Get-VerificationModulePresentation.ps1')
    . (Join-Path $script:RepoRoot 'Tools/Private/Get-VerificationNotCheckedAccounting.ps1')
    . (Join-Path $script:RepoRoot 'Tools/Private/New-HardeningHtmlReport.ps1')

    function Get-TestNotCheckedDetailFixture {
        param(
            [int]$AffectedTargetCount = 1,
            [ValidateSet('ByChoice','NoSavedChoice','CannotVerify')]
            [string]$Disposition = 'ByChoice',
            [string]$Actual = 'Excluded by saved test choice.'
        )
        $source = switch ($Disposition) {
            'ByChoice' { 'ApplyIntent' }
            'NoSavedChoice' { 'None' }
            'CannotVerify' { 'RuntimeQuery' }
        }
        [PSCustomObject]@{
            Setting='Structured NotChecked target'; Path='HKLM:\SOFTWARE\NoIDPrivacy'
            Expected='Selected only when requested'; Actual=$Actual
            CheckState='NotChecked'
            VerificationDisposition=$Disposition
            VerificationEvidenceSource=$source
            VerificationReasonCode="Test.$Disposition"
            AffectedTargetCount=$AffectedTargetCount
        }
    }

    function Get-PrivacyReportResultFixture {
        param(
            [AllowNull()][string]$Mode,
            [int]$Total,
            [int]$Passed,
            [int]$Failed,
            [int]$NotChecked,
            [int]$NotApplicable
        )

        $scorecardDefinitions = @(
            [PSCustomObject]@{ Mode='MSRecommended'; Matched=29; ApplicableTotal=30; Mismatched=1; NotApplicable=6; MismatchDetails=@('SHOULD-NOT-RENDER-MSRECOMMENDED') }
            [PSCustomObject]@{ Mode='Strict'; Matched=54; ApplicableTotal=54; Mismatched=0; NotApplicable=7; MismatchDetails=@() }
            [PSCustomObject]@{ Mode='Paranoid'; Matched=55; ApplicableTotal=81; Mismatched=26; NotApplicable=9; MismatchDetails=@('SHOULD-NOT-RENDER-PARANOID') }
        )
        $fixtureNotCheckedDetails = if ($NotChecked -gt 0) {
            @(Get-TestNotCheckedDetailFixture -AffectedTargetCount $NotChecked)
        }
        else { @() }
        $privacyCategory = [PSCustomObject]@{
            Category='Privacy'; Total=$Total; Passed=$Passed; Failed=$Failed
            NotChecked=$NotChecked; NotCheckedDeliberate=$NotChecked; NotApplicable=$NotApplicable
            NotCheckedNoSavedChoice=0; NotCheckedCannotVerify=0
            PassedDetails=@([PSCustomObject]@{
                    Setting='Readable Privacy evidence'; Path='HKLM:\SOFTWARE\NoIDPrivacy'
                    Expected='DWord/{"Value":1}'; Actual='DWord/{"Value":1}'
                })
            FailedDetails=@(); NotCheckedDetails=$fixtureNotCheckedDetails; NotApplicableDetails=@()
        }
        return [PSCustomObject]@{
            SelectedModules=@('SecurityBaseline','ASR','DNS','Privacy','AntiAI','EdgeHardening','AdvancedSecurity')
            TotalSettings=$Total; ProductTargetInventory=117; Verified=$Passed; Failed=$Failed
            NotChecked=$NotChecked; NotCheckedDeliberate=$NotChecked
            NotCheckedNoSavedChoice=0; NotCheckedCannotVerify=0
            NotApplicable=$NotApplicable; AppliedScopeRun=$false
            PrivacyMode=$Mode
            # The verifier emits this on every run. The report needs it to tell
            # "we counted the maximum Privacy scope" apart from "we counted a
            # smaller one" - it must never infer that magnitude from the mere
            # absence of PrivacyMode, which asserted the maximum for fail-closed
            # runs that had in fact counted the 63-target minimum.
            PrivacyModeTotals=[PSCustomObject]@{ MSRecommended=63; Strict=88; Paranoid=117 }
            PrivacyProfileScorecards=$scorecardDefinitions
            IntentReference='Durable Apply intent recorded 2026-08-15T22:50:45.7098053Z'
            AllSettings=@($privacyCategory)
        }
    }
}

Describe 'Privacy verification presentation' {
    It 'builds one reconciled selected-profile verdict for <Mode>' -TestCases @(
        @{ Mode='MSRecommended'; Total=63; Passed=30; NotApplicable=33 }
        @{ Mode='Strict'; Total=88; Passed=54; NotApplicable=34 }
        @{ Mode='Paranoid'; Total=117; Passed=81; NotApplicable=36 }
    ) {
        param($Mode, $Total, $Passed, $NotApplicable)

        $presentation = Get-PrivacyVerificationPresentation `
            -Mode $Mode -Total $Total -Passed $Passed -Failed 0 `
            -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable $NotApplicable

        $presentation.Mode | Should -BeExactly $Mode
        $presentation.Status | Should -BeExactly 'VERIFIED'
        $presentation.Evaluated | Should -Be $Passed
        ($presentation.Passed + $presentation.Failed + $presentation.NotChecked + $presentation.NotApplicable) |
            Should -Be $presentation.Total
    }

    It 'rejects presentation buckets that do not reconcile' {
        {
            Get-PrivacyVerificationPresentation -Mode Strict -Total 88 -Passed 54 `
                -Failed 0 -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 33
        } | Should -Throw '*do not reconcile*'
    }

    It 'keeps intentional exclusions verified while unproven Privacy targets stay incomplete' {
        $intentional = Get-PrivacyVerificationPresentation -Mode Strict -Total 88 `
            -Passed 53 -Failed 0 -NotChecked 1 -NotCheckedDeliberate 1 -NotApplicable 34
        $unproven = Get-PrivacyVerificationPresentation -Mode Strict -Total 88 `
            -Passed 53 -Failed 0 -NotChecked 1 -NotCheckedDeliberate 0 -NotApplicable 34

        $intentional.Status | Should -BeExactly 'VERIFIED'
        $unproven.Status | Should -BeExactly 'INCOMPLETE'
        $unproven.NotCheckedUnresolved | Should -Be 1
    }

    It 'builds one incomplete line without guessing or printing competing profiles' {
        $presentation = Get-PrivacyUnavailablePresentation -Total 117

        $presentation.Status | Should -BeExactly 'INCOMPLETE'
        $presentation.Total | Should -Be 117
        $presentation.SummaryLine | Should -BeExactly `
            'No saved selected profile; 117 targets remain unproven.'
        $presentation.SummaryLine | Should -Not -Match 'MSRecommended|Strict|Paranoid'
        $presentation.DetailActual | Should -BeExactly `
            'No saved Privacy profile; this row represents all 117 declared Privacy targets whose selected profile cannot be inferred.'
    }
}

Describe 'Shared console module presentation' {
    It 'marks a fully proven module verified' {
        $presentation = Get-VerificationModulePresentation -Name DNS -Total 5 `
            -Passed 5 -Failed 0 -NotChecked 0 -NotCheckedDeliberate 0 `
            -NotApplicable 0 -Summary '5/5 checks passed; 0 failed.'

        $presentation.Status | Should -BeExactly 'VERIFIED'
        $presentation.StatusLine | Should -BeExactly 'DNS: [VERIFIED]'
        $presentation.Color | Should -BeExactly 'Green'
    }

    It 'keeps authoritatively intentional exclusions verified without calling them passed' {
        $presentation = Get-VerificationModulePresentation -Name DNS -Total 5 `
            -Passed 0 -Failed 0 -NotChecked 5 -NotCheckedDeliberate 5 `
            -NotApplicable 0 -Summary 'DNS takeover deliberately skipped by saved Apply choice.'

        $presentation.Status | Should -BeExactly 'VERIFIED'
        $presentation.NotCheckedUnresolved | Should -Be 0
        $presentation.SummaryLine | Should -Not -Match '0/5 verified'
    }

    It 'marks unresolved evidence incomplete and mismatches failed' {
        $incomplete = Get-VerificationModulePresentation -Name AntiAI -Total 47 `
            -Passed 4 -Failed 0 -NotChecked 43 -NotCheckedDeliberate 0 `
            -NotApplicable 0 -Summary '43 targets unproven.'
        $failed = Get-VerificationModulePresentation -Name Registry -Total 335 `
            -Passed 6 -Failed 329 -NotChecked 0 -NotCheckedDeliberate 0 `
            -NotApplicable 0 -Summary '329 failed.'

        $incomplete.Status | Should -BeExactly 'INCOMPLETE'
        $incomplete.Color | Should -BeExactly 'Yellow'
        $failed.Status | Should -BeExactly 'FAILED'
        $failed.Color | Should -BeExactly 'Red'
    }

    It 'marks a wholly unsupported module not applicable instead of verified' {
        $presentation = Get-VerificationModulePresentation -Name EdgeHardening -Total 26 `
            -Passed 0 -Failed 0 -NotChecked 0 -NotCheckedDeliberate 0 `
            -NotApplicable 26 -Summary '26 targets are not applicable.'

        $presentation.Status | Should -BeExactly 'NOT APPLICABLE'
        $presentation.StatusLine | Should -BeExactly 'EdgeHardening: [NOT APPLICABLE]'
        $presentation.Color | Should -BeExactly 'DarkGray'
    }

    It 'rejects unreconciled or overclaimed evidence buckets' {
        {
            Get-VerificationModulePresentation -Name DNS -Total 5 -Passed 4 -Failed 0 `
                -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0 -Summary 'invalid'
        } | Should -Throw '*does not reconcile*'
        {
            Get-VerificationModulePresentation -Name DNS -Total 5 -Passed 0 -Failed 0 `
                -NotChecked 5 -NotCheckedDeliberate 6 -NotApplicable 0 -Summary 'invalid'
        } | Should -Throw '*more deliberate exclusions*'
    }
}

Describe 'Structured NotChecked accounting' {
    It 'reconciles one explicit Privacy row to all 117 affected targets' {
        $detail = Get-TestNotCheckedDetailFixture -AffectedTargetCount 117 `
            -Disposition NoSavedChoice -Actual 'Wording may change without changing classification.'

        $accounting = Get-VerificationNotCheckedAccounting `
            -Details @($detail) -ExpectedCount 117 -Context 'Privacy test'

        $accounting.Total | Should -Be 117
        $accounting.NoSavedChoice | Should -Be 117
        $accounting.DetailRows | Should -Be 1
        $accounting.Unresolved | Should -Be 117
    }

    It 'derives disposition from structured fields rather than human wording' {
        $first = Get-TestNotCheckedDetailFixture -Disposition ByChoice -Actual 'Original wording.'
        $second = Get-TestNotCheckedDetailFixture -Disposition ByChoice -Actual 'Completely different wording.'

        (Get-VerificationNotCheckedAccounting -Details @($first) -ExpectedCount 1).ByChoice |
            Should -Be 1
        (Get-VerificationNotCheckedAccounting -Details @($second) -ExpectedCount 1).ByChoice |
            Should -Be 1
    }

    It 'accepts the Windows-owned choice marker as a distinct ByChoice evidence source' {
        $detail = Get-TestNotCheckedDetailFixture -Disposition ByChoice
        $detail.VerificationEvidenceSource = 'WindowsState'
        $detail.VerificationReasonCode = 'AdvancedSecurity.WindowsUpdateUserOptIn'

        (Get-VerificationNotCheckedAccounting -Details @($detail) -ExpectedCount 1).ByChoice |
            Should -Be 1
    }

    It 'throws when target weights do not reconcile or evidence metadata is missing' {
        $wrongWeight = Get-TestNotCheckedDetailFixture -AffectedTargetCount 116 -Disposition NoSavedChoice
        {
            Get-VerificationNotCheckedAccounting -Details @($wrongWeight) `
                -ExpectedCount 117 -Context 'Privacy test'
        } | Should -Throw '*cover 116 target(s); expected 117*'

        $missingReason = Get-TestNotCheckedDetailFixture
        $missingReason.PSObject.Properties.Remove('VerificationReasonCode')
        {
            Get-VerificationNotCheckedAccounting -Details @($missingReason) -ExpectedCount 1
        } | Should -Throw '*without VerificationReasonCode*'

        $wrongSource = Get-TestNotCheckedDetailFixture -Disposition NoSavedChoice
        $wrongSource.VerificationEvidenceSource = 'ApplyIntent'
        {
            Get-VerificationNotCheckedAccounting -Details @($wrongSource) -ExpectedCount 1
        } | Should -Throw "*invalid evidence source 'ApplyIntent' for NoSavedChoice*"
    }
}

Describe 'Privacy HTML summary UX' {
    BeforeEach {
        Mock Get-CimInstance {
            [PSCustomObject]@{ Caption='Microsoft Windows 11 Pro'; BuildNumber='26200' }
        }
    }

    It 'keeps <Mode> only in Verification Scope, omits profile comparisons and preserves module evidence' -TestCases @(
        @{ Mode='MSRecommended'; Total=63; Passed=30; NotApplicable=33 }
        @{ Mode='Strict'; Total=88; Passed=54; NotApplicable=34 }
        @{ Mode='Paranoid'; Total=117; Passed=81; NotApplicable=36 }
    ) {
        param($Mode, $Total, $Passed, $NotApplicable)

        $result = Get-PrivacyReportResultFixture -Mode $Mode -Total $Total -Passed $Passed `
            -Failed 0 -NotChecked 0 -NotApplicable $NotApplicable
        $output = Join-Path $TestDrive "$Mode.html"
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match ([regex]::Escape("$Total targets (Privacy mode: $Mode)"))
        $verificationScopePattern = '<div class="stat-value">{0}</div>\s*' +
            '<div class="stat-label">Verification Scope</div>'
        $html | Should -Match ($verificationScopePattern -f $Total)
        $html | Should -Not -Match 'product targets'
        $html | Should -Match "100% of $Passed required checks passed"
        ([regex]::Matches($html, [regex]::Escape($Mode))).Count | Should -Be 1
        $html | Should -Match '<div class="module-section" id="module-Privacy">'
        $html | Should -Match "<strong>$Passed</strong>"
        $html | Should -Not -Match '<span class="badge '
        $html | Should -Not -Match '<p class="verdict-detail">'
        $html | Should -Not -Match '<section class="privacy-verdict'
        $html | Should -Not -Match '<details class="profile-comparison">'
        $html | Should -Match '<table class="settings-table">'
        $html | Should -Match '<th>Setting</th>'
        $html | Should -Match '<th>Path/Policy</th>'
        $html | Should -Match '<th>Expected</th>'
        $html | Should -Match '<th>Actual</th>'
        $html | Should -Match '<th>Status</th>'
        $html | Should -Match 'Readable Privacy evidence'
        $html | Should -Match 'DWord/1'
        $html | Should -Not -Match 'Apply intent reference'
        $html | Should -Not -Match 'Durable Apply intent recorded'
        $html | Should -Not -Match 'First mismatches'
        $html | Should -Not -Match 'SHOULD-NOT-RENDER'
    }

    It 'keeps module evidence interactive on screen and offers deterministic summary and detailed print modes' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 54 `
            -Failed 0 -NotChecked 0 -NotApplicable 34
        $output = Join-Path $TestDrive 'strict-interactive.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match 'onclick="toggleModule\(''module-Privacy''\)"'
        $html | Should -Match '<span class="expand-icon">'
        $html | Should -Match '<div class="module-content">'
        $html | Should -Match 'id="searchBox"'
        $html | Should -Match "filterSettings\('notapplicable', this\)"
        $html | Should -Match 'function toggleModule\(moduleId\)'
        $html | Should -Match '(?s)@media print.*\.module-section\.collapsed \.module-content.*display: block !important;.*max-height: none !important;.*overflow: visible !important;'
        $html | Should -Match '(?s)html\[data-print-mode="summary"\] \.module-content.*display: none !important;'
        $html | Should -Match '(?s)html\[data-print-mode="summary"\] \.module-header.*page-break-after: auto;.*break-after: auto;'
        $html | Should -Match '(?s)html\[data-print-mode="detailed"\] \.module-content.*display: block !important;.*max-height: none !important;.*overflow: visible !important;'
        $html | Should -Match 'display: table-header-group;'
        $html | Should -Match '(?s)\.settings-table tr\s*\{.*break-inside: avoid;'
        $html | Should -Match '(?s)@media print.*\.footer\s*\{\s*padding: 0\.35rem 1rem;\s*font-size: 0\.65rem;\s*line-height: 1\.2;\s*white-space: nowrap;'
        $html | Should -Match "(?s)@media print.*\.footer p \+ p::before\s*\{\s*content: ' \\0000b7  ';"
        $html | Should -Match 'onclick="printReport\(''summary''\)">Print Summary</button>'
        $html | Should -Match 'onclick="printReport\(''detailed''\)">Print Detailed Report</button>'
        $html | Should -Match 'function printReport\(mode\)'
        $html | Should -Match "document\.documentElement\.setAttribute\('data-print-mode', mode\)"
        $html | Should -Match "window\.addEventListener\('afterprint', clearPrintMode, \{ once: true \}\)"
    }

    It 'keeps balanced spacing between summary cards, evidence bar, and controls' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 54 `
            -Failed 0 -NotChecked 0 -NotApplicable 34
        $output = Join-Path $TestDrive 'strict-spacing.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '(?s)\.dashboard\s*\{\s*padding: 2rem 2rem 1rem;'
        $html | Should -Match '(?s)\.stats-grid\s*\{.*?margin-bottom: 1\.75rem;'
        $html | Should -Match '(?s)\.progress-section\s*\{\s*margin: 0 0 1\.75rem;'
        $html | Should -Match '(?s)\.controls\s*\{.*margin-bottom: 0;'
        $html | Should -Match '(?s)\.modules-container\s*\{\s*padding: 0 2rem 1rem;'
    }

    It 'rejects a selected scope larger than the declared product inventory' {
        $result = Get-PrivacyReportResultFixture -Mode Paranoid -Total 117 -Passed 81 `
            -Failed 0 -NotChecked 0 -NotApplicable 36
        $result.ProductTargetInventory = 116
        $output = Join-Path $TestDrive 'invalid-inventory.html'

        { New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName } |
            Should -Throw '*scope exceeds product inventory*'
    }

    It 'rejects a category whose displayed NotChecked rows cover the wrong target count' {
        $result = Get-PrivacyReportResultFixture -Mode $null -Total 117 -Passed 0 `
            -Failed 0 -NotChecked 117 -NotApplicable 0
        $result.AllSettings[0].NotCheckedDetails = @(
            Get-TestNotCheckedDetailFixture -AffectedTargetCount 116 -Disposition NoSavedChoice
        )
        $output = Join-Path $TestDrive 'invalid-notchecked-weight.html'

        { New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName } |
            Should -Throw '*cover 116 target(s); expected 117*'
    }

    It 'renders a fully verified result as one entirely green 100 percent bar' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 54 `
            -Failed 0 -NotChecked 0 -NotApplicable 34
        $output = Join-Path $TestDrive 'strict-result-complete.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="progress-bar-segment passed" style="width: 100%;"></div>'
        $html | Should -Match '<div class="progress-bar-segment failed" style="width: 0%;"></div>'
        $html | Should -Match '<div class="progress-bar-segment unproven" style="width: 0%;"></div>'
        $html | Should -Match '100% of 54 required checks passed'
        $html | Should -Not -Match 'Evidence coverage:'
    }

    It 'renders failed checks as the red remainder of the required result bar' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 53 `
            -Failed 1 -NotChecked 0 -NotApplicable 34
        $output = Join-Path $TestDrive 'strict-result-failed.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="progress-bar-segment passed" style="width: 98\.1481%;"></div>'
        $html | Should -Match '<div class="progress-bar-segment failed" style="width: 1\.8519%;"></div>'
        $html | Should -Match '98\.1% of 54 required checks passed &middot; 1 failed'
    }

    It 'renders unresolved checks as the yellow remainder of an incomplete result bar' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 53 `
            -Failed 0 -NotChecked 1 -NotApplicable 34
        $result.NotCheckedDeliberate = 0
        $result.NotCheckedNoSavedChoice = 1
        $result.AllSettings[0].NotCheckedDeliberate = 0
        $result.AllSettings[0].NotCheckedNoSavedChoice = 1
        $result.AllSettings[0].NotCheckedDetails = @(
            Get-TestNotCheckedDetailFixture -Disposition NoSavedChoice -Actual 'No saved test choice.'
        )
        $output = Join-Path $TestDrive 'strict-result-incomplete.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="progress-bar-segment passed" style="width: 98\.1481%;"></div>'
        $html | Should -Match '<div class="progress-bar-segment unproven" style="width: 1\.8519%;"></div>'
        $html | Should -Match '98\.1% of 54 required checks proven &middot; 1 unproven'
    }

    It 'renders a total verification failure as zero percent with a fully red bar' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 0 `
            -Failed 54 -NotChecked 0 -NotApplicable 34
        $output = Join-Path $TestDrive 'strict-result-total-failure.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="progress-bar-segment passed" style="width: 0%;"></div>'
        $html | Should -Match '<div class="progress-bar-segment failed" style="width: 100%;"></div>'
        $html | Should -Match '0% of 54 required checks passed &middot; 54 failed'
    }

    It 'shows failed counts without restoring the removed header verdict' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 53 `
            -Failed 1 -NotChecked 0 -NotApplicable 34
        $output = Join-Path $TestDrive 'strict-failed.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="stat-value danger">1</div>'
        $html | Should -Match '<span>Failed:</span>\s*<strong>1</strong>'
        $html | Should -Not -Match '<span class="badge '
        $html | Should -Not -Match '<section class="privacy-verdict'
        $html | Should -Not -Match '100% VERIFIED'
    }

    It 'labels fully intentional exclusions as a user choice in aggregate counts' {
        $result = Get-PrivacyReportResultFixture -Mode MSRecommended -Total 63 -Passed 30 `
            -Failed 0 -NotChecked 27 -NotApplicable 6
        $output = Join-Path $TestDrive 'msrecommended-intentional.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="stat-value warning">27</div>'
        $html | Should -Match '<div class="stat-label">Excluded by Choice</div>'
        $html | Should -Match '<span>By choice:</span>\s*<strong>27</strong>'
        $html | Should -Match '>By choice</button>'
        $html | Should -Not -Match '<span class="badge '
        $html | Should -Not -Match '<section class="privacy-verdict'
    }

    It 'labels an authoritatively classified detail row BY CHOICE without changing its NotChecked bucket' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 53 `
            -Failed 0 -NotChecked 1 -NotApplicable 34
        $result.AllSettings[0].NotCheckedDetails = @([PSCustomObject]@{
                Setting='Optional target'; Path='HKLM:\SOFTWARE\NoIDPrivacy'
                Expected='Selected only when requested'; Actual='Not selected by saved Apply choice'
                CheckState='NotChecked'
                VerificationDisposition='ByChoice'
                VerificationEvidenceSource='ApplyIntent'
                VerificationReasonCode='Test.ByChoice'
                AffectedTargetCount=1
            })
        $output = Join-Path $TestDrive 'strict-by-choice-row.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match 'status-badge bychoice'
        $html | Should -Match '>BY CHOICE</span>'
        $html | Should -Match 'data-verification-reason="Test.ByChoice"'
        $html | Should -Match 'data-evidence-source="ApplyIntent"'
        $html | Should -Not -Match 'status-badge notchecked[^>]*>.*Optional target'
    }

    It 'labels a runtime verification failure as CANNOT VERIFY' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 53 `
            -Failed 0 -NotChecked 1 -NotApplicable 34
        $result.NotCheckedDeliberate = 0
        $result.NotCheckedCannotVerify = 1
        $result.AllSettings[0].NotCheckedDeliberate = 0
        $result.AllSettings[0].NotCheckedCannotVerify = 1
        $result.AllSettings[0].NotCheckedDetails = @(
            Get-TestNotCheckedDetailFixture -Disposition CannotVerify -Actual 'Could not verify the runtime API.'
        )
        $output = Join-Path $TestDrive 'strict-cannot-verify.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="stat-label">Could Not Verify</div>'
        $html | Should -Match '<span>Could not verify:</span>\s*<strong>1</strong>'
        $html | Should -Match 'status-badge cannotverify'
        $html | Should -Match '>CANNOT VERIFY</span>'
    }

    It 'uses the neutral NotChecked label when structured reasons are mixed' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 52 `
            -Failed 0 -NotChecked 2 -NotApplicable 34
        $result.NotCheckedDeliberate = 1
        $result.NotCheckedCannotVerify = 1
        $result.AllSettings[0].NotCheckedDeliberate = 1
        $result.AllSettings[0].NotCheckedCannotVerify = 1
        $result.AllSettings[0].NotCheckedDetails = @(
            (Get-TestNotCheckedDetailFixture -Disposition ByChoice),
            (Get-TestNotCheckedDetailFixture -Disposition CannotVerify -Actual 'Could not verify the runtime API.')
        )
        $output = Join-Path $TestDrive 'strict-needs-evidence.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="stat-label">Settings Not Checked</div>'
        $html | Should -Match '<span>Not checked:</span>\s*<strong>2</strong>'
        $html | Should -Match '>Not checked</button>'
        $html | Should -Match '>BY CHOICE</span>'
        $html | Should -Match '>CANNOT VERIFY</span>'
    }

    It 'shows no profile or technical comparison when Apply intent is unavailable' {
        $result = Get-PrivacyReportResultFixture -Mode $null -Total 117 -Passed 0 `
            -Failed 0 -NotChecked 117 -NotApplicable 0
        $result.NotCheckedDeliberate = 0
        $result.NotCheckedNoSavedChoice = 117
        $result.AllSettings[0].NotCheckedDeliberate = 0
        $result.AllSettings[0].NotCheckedNoSavedChoice = 117
        $result.AllSettings[0].NotCheckedDetails = @(
            Get-TestNotCheckedDetailFixture -AffectedTargetCount 117 -Disposition NoSavedChoice `
                -Actual 'No saved Privacy profile; this row represents all 117 declared Privacy targets.'
        )
        $output = Join-Path $TestDrive 'privacy-no-intent.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="stat-value warning">117</div>'
        $html | Should -Match '<div class="stat-label">No Saved Choice</div>'
        $html | Should -Match 'NO SAVED CHOICE &middot; 117 TARGETS'
        $html | Should -Match 'represents all 117 declared Privacy targets'
        $html | Should -Not -Match 'Privacy mode:'
        $html | Should -Match '117 targets \(Privacy profile unproven; maximum scope used\)'
        $html | Should -Not -Match 'Selected profile unavailable'
        $html | Should -Not -Match 'Informational live profile comparison'
        $html | Should -Not -Match '<section class="privacy-verdict'
        $html | Should -Not -Match '<details class="profile-comparison">'
        $html | Should -Not -Match '100% VERIFIED'
        $html | Should -Not -Match 'Apply intent reference'
    }

    It 'redacts user SIDs, profile paths and e-mail addresses in every rendered cell' {
        # The report promises always-on redaction, yet no rendered fixture ever
        # contained anything TO redact - every path was HKLM:\SOFTWARE\NoIDPrivacy.
        # Real reports carry ~25 HKU:\S-1-5-21-... user-hive paths per run, and
        # fail-closed Actual cells embed exception messages with full profile
        # paths. Render exactly that and prove the promise on the output.
        $result = Get-PrivacyReportResultFixture -Mode 'Strict' -Total 88 -Passed 88 `
            -Failed 0 -NotChecked 0 -NotApplicable 0
        $result.AllSettings[0].PassedDetails = @(
            [PSCustomObject]@{
                Setting = 'User-hive Privacy target'
                Path = 'HKU:\S-1-5-21-1004336348-1177238915-682003330-1001\Software\Microsoft\Test'
                Expected = 'DWord/{"Value":1}'; Actual = 'DWord/{"Value":1}'
            }
        )
        $result.AllSettings[0].FailedDetails = @(
            [PSCustomObject]@{
                Setting = 'Fail-closed evidence with an embedded path'
                Path = 'HKLM:\SOFTWARE\NoIDPrivacy'
                Expected = 'Readable configuration'
                Actual = "Verification failed closed: Cannot find path 'C:\Users\John Doe\Downloads\noid-privacy\Modules\Privacy\Config\Privacy-Strict.json'. Contact alice.doe@example.com."
            }
        )
        $result.Failed = 1
        $result.AllSettings[0].Failed = 1

        $output = Join-Path $TestDrive 'privacy-redaction.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        # The replacement tokens are present...
        $html | Should -Match '\[USER-SID\]'
        $html | Should -Match '%USERPROFILE%'
        $html | Should -Match '\[EMAIL\]'
        # ...and none of the sensitive raw values survive anywhere in the page.
        # 'Doe' alone is the load-bearing assertion: the old regex stopped at the
        # first space, consumed 'C:\Users\John' and left ' Doe\Downloads...' in
        # the report - so checking only for the full phrase would miss exactly
        # the leak this test exists to prevent.
        # Word-bounded: a bare 'Doe' substring match would also fire on
        # legitimate copy like "does", failing the test without any leak.
        $html | Should -Not -Match 'S-1-5-21-1004336348'
        $html | Should -Not -Match '\bJohn\b'
        $html | Should -Not -Match '\bDoe\b' -Because 'a profile folder with a space must be redacted in full, not up to the first space'
        $html | Should -Not -Match '\balice\b'
    }

    It 'never claims the maximum Privacy scope for a run that counted a smaller one' {
        # A fail-closed run whose Privacy try threw before $results.PrivacyMode was
        # set: PrivacyMode is $null, but only 63 of the 117 declared targets were
        # counted. The label used to assert "maximum scope used" purely because the
        # mode was absent, overstating the audit by nearly a factor of two.
        $result = Get-PrivacyReportResultFixture -Mode $null -Total 63 -Passed 0 `
            -Failed 63 -NotChecked 0 -NotApplicable 0
        $output = Join-Path $TestDrive 'privacy-partial-scope.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Not -Match 'maximum scope used'
        $html | Should -Match 'Privacy profile unproven; 63 Privacy targets counted'
    }

    It 'shows an unproven count without a separate Privacy card' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 88 -Passed 53 `
            -Failed 0 -NotChecked 1 -NotApplicable 34
        $result.NotCheckedDeliberate = 0
        $result.NotCheckedNoSavedChoice = 1
        $result.AllSettings[0].NotCheckedDeliberate = 0
        $result.AllSettings[0].NotCheckedNoSavedChoice = 1
        $result.AllSettings[0].NotCheckedDetails = @([PSCustomObject]@{
                Setting='Unproven target'; Path='HKLM:\SOFTWARE\NoIDPrivacy'
                Expected='Saved selection'; Actual='Saved selection unavailable'
                CheckState='NotChecked'
                VerificationDisposition='NoSavedChoice'
                VerificationEvidenceSource='None'
                VerificationReasonCode='Test.NoSavedChoice'
                AffectedTargetCount=1
            })
        $output = Join-Path $TestDrive 'privacy-unproven.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="stat-value warning">1</div>'
        $html | Should -Match '<div class="stat-label">No Saved Choice</div>'
        $html | Should -Match '<span>No saved choice:</span>\s*<strong>1</strong>'
        $html | Should -Match 'status-badge nosavedchoice'
        $html | Should -Match '>NO SAVED CHOICE</span>'
        $html | Should -Not -Match '<span class="badge '
        $html | Should -Not -Match '<section class="privacy-verdict'
        $html | Should -Not -Match '100% VERIFIED'
    }
}
