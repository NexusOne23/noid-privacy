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
            TotalSettings=$Total; ProductTargetInventory=119; Verified=$Passed; Failed=$Failed
            NotChecked=$NotChecked; NotCheckedDeliberate=$NotChecked
            NotCheckedNoSavedChoice=0; NotCheckedCannotVerify=0
            NotApplicable=$NotApplicable; AppliedScopeRun=$false
            PrivacyMode=$Mode
            # The verifier emits this on every run. The report needs it to tell
            # "we counted the maximum Privacy scope" apart from "we counted a
            # smaller one"; it must never infer that magnitude from the mere
            # absence of PrivacyMode.
            PrivacyModeTotals=[PSCustomObject]@{ MSRecommended=65; Strict=90; Paranoid=119 }
            PrivacyProfileScorecards=$scorecardDefinitions
            IntentReference='Durable Apply intent recorded 2026-08-15T22:50:45.7098053Z'
            AllSettings=@($privacyCategory)
        }
    }
}

Describe 'Privacy verification presentation' {
    It 'builds one reconciled selected-profile verdict for <Mode>' -TestCases @(
        @{ Mode='MSRecommended'; Total=65; Passed=30; NotApplicable=35 }
        @{ Mode='Strict'; Total=90; Passed=54; NotApplicable=36 }
        @{ Mode='Paranoid'; Total=119; Passed=81; NotApplicable=38 }
    ) {
        param($Mode, $Total, $Passed, $NotApplicable)

        $presentation = Get-PrivacyVerificationPresentation `
            -Mode $Mode -Total $Total -Passed $Passed -Failed 0 `
            -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable $NotApplicable

        $presentation.Mode | Should -BeExactly $Mode
        $presentation.Status | Should -BeExactly 'PASSED'
        $presentation.Evaluated | Should -Be $Passed
        ($presentation.Passed + $presentation.Failed + $presentation.NotChecked + $presentation.NotApplicable) |
            Should -Be $presentation.Total
    }

    It 'rejects presentation buckets that do not reconcile' {
        {
            Get-PrivacyVerificationPresentation -Mode Strict -Total 90 -Passed 54 `
                -Failed 0 -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 35
        } | Should -Throw '*do not reconcile*'
    }

    It 'passes intentional exclusions while a not-proven Privacy target fails' {
        $intentional = Get-PrivacyVerificationPresentation -Mode Strict -Total 90 `
            -Passed 53 -Failed 0 -NotChecked 1 -NotCheckedDeliberate 1 -NotApplicable 36
        $notProven = Get-PrivacyVerificationPresentation -Mode Strict -Total 90 `
            -Passed 53 -Failed 0 -NotChecked 1 -NotCheckedDeliberate 0 -NotApplicable 36

        $intentional.Status | Should -BeExactly 'PASSED'
        $notProven.Status | Should -BeExactly 'FAILED'
        $notProven.NotCheckedUnresolved | Should -Be 1
    }

    It 'fails a missing Privacy profile without guessing or printing competing profiles' {
        $presentation = Get-PrivacyUnavailablePresentation -Total 119

        $presentation.Status | Should -BeExactly 'FAILED'
        $presentation.Total | Should -Be 119
        $presentation.NoteLine | Should -BeExactly `
            'Not proven: no saved Privacy profile; the selected profile is never guessed from the live state.'
        $presentation.NoteLine | Should -Not -Match 'MSRecommended|Strict|Paranoid'
        $presentation.DetailActual | Should -BeExactly `
            'No saved Privacy profile; this row represents all 119 declared Privacy targets whose selected profile cannot be inferred.'
    }
}

Describe 'Shared console module presentation' {
    It 'formats one count line with the same four words on every surface' {
        Format-VerificationCountsLine -Passed 58 -Mismatched 441 -NotProven 206 -ByChoice 0 `
            -NotApplicable 7 -Total 712 |
            Should -BeExactly '58 passed; 647 failed (441 mismatched, 206 not proven); 0 by choice; 7 not applicable (712 targets)'
        Format-VerificationCountsLine -Passed 4 -Mismatched 0 -NotProven 50 -ByChoice 0 `
            -NotApplicable 0 -Total 54 |
            Should -BeExactly '4 passed; 50 failed (not proven); 0 by choice; 0 not applicable (54 targets)'
        Format-VerificationCountsLine -Passed 625 -Mismatched 0 -NotProven 0 -ByChoice 30 `
            -NotApplicable 57 -Total 712 |
            Should -BeExactly '625 passed; 0 failed; 30 by choice; 57 not applicable (712 targets)'
    }

    It 'marks a fully proven module passed' {
        $presentation = Get-VerificationModulePresentation -Name DNS -Total 5 `
            -Passed 5 -Failed 0 -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0

        $presentation.Status | Should -BeExactly 'PASSED'
        $presentation.StatusLine | Should -BeExactly 'DNS: [PASSED]'
        $presentation.SummaryLine | Should -BeExactly '5 passed; 0 failed; 0 by choice; 0 not applicable (5 targets)'
        $presentation.NoteLine | Should -BeNullOrEmpty
        $presentation.Color | Should -BeExactly 'Green'
    }

    It 'passes authoritatively intentional exclusions without calling them passed checks' {
        $presentation = Get-VerificationModulePresentation -Name DNS -Total 5 `
            -Passed 0 -Failed 0 -NotChecked 5 -NotCheckedDeliberate 5 -NotApplicable 0 `
            -Note 'By choice: the saved Apply choice skips the DNS takeover.'

        $presentation.Status | Should -BeExactly 'PASSED'
        $presentation.NotCheckedUnresolved | Should -Be 0
        $presentation.SummaryLine | Should -BeExactly '0 passed; 0 failed; 5 by choice; 0 not applicable (5 targets)'
        $presentation.NoteLine | Should -BeExactly 'By choice: the saved Apply choice skips the DNS takeover.'
    }

    It 'fails not-proven evidence and mismatches alike and keeps their causes apart' {
        $notProven = Get-VerificationModulePresentation -Name AntiAI -Total 54 `
            -Passed 4 -Failed 0 -NotChecked 50 -NotCheckedDeliberate 0 -NotApplicable 0
        $failed = Get-VerificationModulePresentation -Name Registry -Total 335 `
            -Passed 6 -Failed 329 -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0

        $notProven.Status | Should -BeExactly 'FAILED'
        $notProven.Color | Should -BeExactly 'Red'
        $notProven.SummaryLine | Should -BeExactly '4 passed; 50 failed (not proven); 0 by choice; 0 not applicable (54 targets)'
        $notProven.NoteLine | Should -BeExactly 'Not proven: each report row names the missing evidence.'
        $failed.Status | Should -BeExactly 'FAILED'
        $failed.Color | Should -BeExactly 'Red'
        $failed.SummaryLine | Should -BeExactly '6 passed; 329 failed; 0 by choice; 0 not applicable (335 targets)'
    }

    It 'marks a wholly unsupported module not applicable instead of passed' {
        $presentation = Get-VerificationModulePresentation -Name EdgeHardening -Total 31 `
            -Passed 0 -Failed 0 -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 31

        $presentation.Status | Should -BeExactly 'NOT APPLICABLE'
        $presentation.StatusLine | Should -BeExactly 'EdgeHardening: [NOT APPLICABLE]'
        $presentation.Color | Should -BeExactly 'DarkGray'
    }

    It 'rejects unreconciled or overclaimed evidence buckets' {
        {
            Get-VerificationModulePresentation -Name DNS -Total 5 -Passed 4 -Failed 0 `
                -NotChecked 0 -NotCheckedDeliberate 0 -NotApplicable 0
        } | Should -Throw '*does not reconcile*'
        {
            Get-VerificationModulePresentation -Name DNS -Total 5 -Passed 0 -Failed 0 `
                -NotChecked 5 -NotCheckedDeliberate 6 -NotApplicable 0
        } | Should -Throw '*more deliberate exclusions*'
    }
}

Describe 'Structured NotChecked accounting' {
    It 'reconciles one explicit Privacy row to all 119 affected targets' {
        $detail = Get-TestNotCheckedDetailFixture -AffectedTargetCount 119 `
            -Disposition NoSavedChoice -Actual 'Wording may change without changing classification.'

        $accounting = Get-VerificationNotCheckedAccounting `
            -Details @($detail) -ExpectedCount 119 -Context 'Privacy test'

        $accounting.Total | Should -Be 119
        $accounting.NoSavedChoice | Should -Be 119
        $accounting.DetailRows | Should -Be 1
        $accounting.Unresolved | Should -Be 119
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
        $wrongWeight = Get-TestNotCheckedDetailFixture -AffectedTargetCount 118 -Disposition NoSavedChoice
        {
            Get-VerificationNotCheckedAccounting -Details @($wrongWeight) `
                -ExpectedCount 119 -Context 'Privacy test'
        } | Should -Throw '*cover 118 target(s); expected 119*'

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

Describe 'Windows runtime HTML evidence' {
    BeforeEach {
        Mock Get-CimInstance { [pscustomobject]@{ Caption='Windows 11 Pro'; BuildNumber='26100' } }
        $script:RuntimeReport = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 54 `
            -Failed 0 -NotChecked 0 -NotApplicable 36
        $script:RuntimeReport | Add-Member -NotePropertyName SecurityBaselineRuntime -NotePropertyValue ([pscustomobject]@{
            Features=@(
                [pscustomobject]@{ Name='Memory integrity (HVCI)'; State='Running'; Label='Running'; EvidenceSource='Win32_DeviceGuard' }
                [pscustomobject]@{ Name='LSA protection'; State='ProtectedAtBoot'; Label='Protected at this boot'; EvidenceSource='CurrentBootWinInit12' }
            )
            Notice='Passed policy checks confirm configuration; runtime protection is shown separately.'
            Guidance='Restart and verify again.'
        })
    }

    It 'renders the recorded observation without re-querying it or changing any result' {
        $before = $script:RuntimeReport | ConvertTo-Json -Depth 10 -Compress
        $output = Join-Path $TestDrive 'runtime-running.html'
        New-HardeningHtmlReport -Results $script:RuntimeReport -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8
        $html | Should -Match 'Windows protection at verification'
        $html | Should -Match 'Memory integrity \(HVCI\)</dt><dd title="Win32_DeviceGuard">Running'
        $html | Should -Match 'Protected at this boot'
        # Every tile label stays on one line in one row of equal tiles.
        $html | Should -Match 'grid-auto-columns: minmax\(max-content, 1fr\)'
        $html | Should -Match '\.runtime-status dt \{[^}]*white-space: nowrap'
        $html | Should -Match '\.runtime-status dd \{[^}]*white-space: nowrap'
        $html | Should -Match '100% of 54 required checks passed'
        $html | Should -Not -Match 'Restart and verify again'
        ($script:RuntimeReport | ConvertTo-Json -Depth 10 -Compress) | Should -BeExactly $before
        Should -Invoke Get-CimInstance -Times 1 -Exactly
    }

    It 'shows an inactive protection alongside passed settings without hiding it in a filtered table' {
        $script:RuntimeReport.SecurityBaselineRuntime.Features[0].State = 'NotRunning'
        $script:RuntimeReport.SecurityBaselineRuntime.Features[0].Label = 'Not running'
        $output = Join-Path $TestDrive 'runtime-inactive.html'
        New-HardeningHtmlReport -Results $script:RuntimeReport -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8
        $html | Should -Match 'Not running'
        $html | Should -Match 'Restart and verify again'
        $html | Should -Match '(?s)<section class="runtime-status".*?</section>\s*<div class="controls">'
        $html | Should -Match 'Passed policy checks confirm configuration; runtime protection is shown separately.'
    }

    It 'encodes and redacts runtime fields before rendering' {
        $script:RuntimeReport.SecurityBaselineRuntime.Features[0].Name = '<script>runtime</script>'
        $script:RuntimeReport.SecurityBaselineRuntime.Features[0].EvidenceSource = '" onmouseover="test'
        $script:RuntimeReport.SecurityBaselineRuntime.Notice = 'private@example.test'
        $output = Join-Path $TestDrive 'runtime-encoded.html'
        New-HardeningHtmlReport -Results $script:RuntimeReport -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8
        $html | Should -Match '&lt;script&gt;runtime&lt;/script&gt;'
        $html | Should -Match '&quot; onmouseover=&quot;test'
        $html | Should -Not -Match '<script>runtime|private@example.test|title="" onmouseover='
        $html | Should -Match '\[EMAIL\]'
    }
}

Describe 'Privacy HTML summary UX' {
    BeforeEach {
        Mock Get-CimInstance {
            [PSCustomObject]@{ Caption='Microsoft Windows 11 Pro'; BuildNumber='26200' }
        }
    }

    It 'keeps <Mode> only in Verification Scope, omits profile comparisons and preserves module evidence' -TestCases @(
        @{ Mode='MSRecommended'; Total=65; Passed=30; NotApplicable=35 }
        @{ Mode='Strict'; Total=90; Passed=54; NotApplicable=36 }
        @{ Mode='Paranoid'; Total=119; Passed=81; NotApplicable=38 }
    ) {
        param($Mode, $Total, $Passed, $NotApplicable)

        $result = Get-PrivacyReportResultFixture -Mode $Mode -Total $Total -Passed $Passed `
            -Failed 0 -NotChecked 0 -NotApplicable $NotApplicable
        $output = Join-Path $TestDrive "$Mode.html"
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match ([regex]::Escape("$Total targets (Privacy profile: $Mode)"))
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
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 54 `
            -Failed 0 -NotChecked 0 -NotApplicable 36
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
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 54 `
            -Failed 0 -NotChecked 0 -NotApplicable 36
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
        $result = Get-PrivacyReportResultFixture -Mode Paranoid -Total 119 -Passed 81 `
            -Failed 0 -NotChecked 0 -NotApplicable 38
        $result.ProductTargetInventory = 118
        $output = Join-Path $TestDrive 'invalid-inventory.html'

        { New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName } |
            Should -Throw '*scope exceeds product inventory*'
    }

    It 'rejects a category whose displayed NotChecked rows cover the wrong target count' {
        $result = Get-PrivacyReportResultFixture -Mode $null -Total 119 -Passed 0 `
            -Failed 0 -NotChecked 119 -NotApplicable 0
        $result.AllSettings[0].NotCheckedDetails = @(
            Get-TestNotCheckedDetailFixture -AffectedTargetCount 118 -Disposition NoSavedChoice
        )
        $output = Join-Path $TestDrive 'invalid-notchecked-weight.html'

        { New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName } |
            Should -Throw '*cover 118 target(s); expected 119*'
    }

    It 'renders a fully verified result as one entirely green 100 percent bar' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 54 `
            -Failed 0 -NotChecked 0 -NotApplicable 36
        $output = Join-Path $TestDrive 'strict-result-complete.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="progress-bar-segment passed" style="width: 100%;"></div>'
        $html | Should -Match '<div class="progress-bar-segment failed" style="width: 0%;"></div>'
        $html | Should -Match '<div class="progress-bar-segment notproven" style="width: 0%;"></div>'
        $html | Should -Match '100% of 54 required checks passed'
        $html | Should -Not -Match 'Evidence coverage:'
    }

    It 'renders failed checks as the red remainder of the required result bar' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 53 `
            -Failed 1 -NotChecked 0 -NotApplicable 36
        $output = Join-Path $TestDrive 'strict-result-failed.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="progress-bar-segment passed" style="width: 98\.1481%;"></div>'
        $html | Should -Match '<div class="progress-bar-segment failed" style="width: 1\.8519%;"></div>'
        $html | Should -Match '98\.1% of 54 required checks passed &middot; 1 failed'
    }

    It 'renders not-proven checks as the hatched failed remainder of the result bar' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 53 `
            -Failed 0 -NotChecked 1 -NotApplicable 36
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
        $html | Should -Match '<div class="progress-bar-segment notproven" style="width: 1\.8519%;"></div>'
        $html | Should -Match '98\.1% of 54 required checks passed &middot; 1 failed \(not proven\)'
        $html | Should -Match '<div class="stat-value danger">1</div>'
        # The split is stated once, in the compliance line; the card shows the total only.
        $html | Should -Match '<div class="stat-label">Failed</div>'
        $html | Should -Not -Match 'stat-note'
    }

    It 'renders a total verification failure as zero percent with a fully red bar' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 0 `
            -Failed 54 -NotChecked 0 -NotApplicable 36
        $output = Join-Path $TestDrive 'strict-result-total-failure.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="progress-bar-segment passed" style="width: 0%;"></div>'
        $html | Should -Match '<div class="progress-bar-segment failed" style="width: 100%;"></div>'
        $html | Should -Match '0% of 54 required checks passed &middot; 54 failed'
    }

    It 'shows failed counts without restoring the removed header verdict' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 53 `
            -Failed 1 -NotChecked 0 -NotApplicable 36
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
        $result = Get-PrivacyReportResultFixture -Mode MSRecommended -Total 65 -Passed 32 `
            -Failed 0 -NotChecked 27 -NotApplicable 6
        $output = Join-Path $TestDrive 'msrecommended-intentional.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="stat-value choice">27</div>'
        $html | Should -Match '<div class="stat-label">By Choice</div>'
        $html | Should -Match '<span>By choice:</span>\s*<strong>27</strong>'
        $html | Should -Match '>By choice</button>'
        $html | Should -Not -Match '<span class="badge '
        $html | Should -Not -Match '<section class="privacy-verdict'
    }

    It 'labels an authoritatively classified detail row BY CHOICE without changing its NotChecked bucket' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 53 `
            -Failed 0 -NotChecked 1 -NotApplicable 36
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
        $html | Should -Match '>By choice</span>'
        $html | Should -Match '<tr class="bychoice" data-verification-reason="Test.ByChoice"'
        $html | Should -Match 'data-evidence-source="ApplyIntent"'
        $html | Should -Not -Match 'status-badge notchecked[^>]*>.*Optional target'
    }

    It 'fails a runtime verification failure as not readable' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 53 `
            -Failed 0 -NotChecked 1 -NotApplicable 36
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

        $html | Should -Match '<div class="stat-value danger">1</div>'
        $html | Should -Match '<span>Failed:</span>\s*<strong>1</strong>'
        $html | Should -Match '<tr class="failed notproven"'
        $html | Should -Match '>Failed &middot; not readable</span>'
        $html | Should -Not -MatchExactly 'CANNOT VERIFY|Could Not Verify|cannotverify'
    }

    It 'splits mixed reasons into BY CHOICE and failed rows with the same card set' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 52 `
            -Failed 0 -NotChecked 2 -NotApplicable 36
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

        $html | Should -Match '<span>Failed:</span>\s*<strong>1</strong>'
        $html | Should -Match '<span>By choice:</span>\s*<strong>1</strong>'
        $html | Should -Match '>By choice</button>'
        $html | Should -Match '>By choice</span>'
        $html | Should -Match '>Failed &middot; not readable</span>'
        $html | Should -Not -Match 'Not checked'
    }

    It 'shows no profile or technical comparison when Apply intent is unavailable' {
        $result = Get-PrivacyReportResultFixture -Mode $null -Total 119 -Passed 0 `
            -Failed 0 -NotChecked 119 -NotApplicable 0
        $result.NotCheckedDeliberate = 0
        $result.NotCheckedNoSavedChoice = 119
        $result.AllSettings[0].NotCheckedDeliberate = 0
        $result.AllSettings[0].NotCheckedNoSavedChoice = 119
        $result.AllSettings[0].NotCheckedDetails = @(
            Get-TestNotCheckedDetailFixture -AffectedTargetCount 119 -Disposition NoSavedChoice `
                -Actual 'No saved Privacy profile; this row represents all 119 declared Privacy targets.'
        )
        $output = Join-Path $TestDrive 'privacy-no-intent.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '<div class="stat-value danger">119</div>'
        $html | Should -Match '<div class="stat-label">Failed</div>'
        $html | Should -Match '119 failed \(not proven\)'
        $html | Should -Match 'Failed &middot; no saved choice &middot; 119 targets'
        $html | Should -Match 'represents all 119 declared Privacy targets'
        $html | Should -Not -Match 'Privacy profile:'
        $html | Should -Match '119 targets \(Privacy profile not proven\)'
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
        $result = Get-PrivacyReportResultFixture -Mode 'Strict' -Total 90 -Passed 90 `
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

    It 'labels a fail-closed run without a proven profile without inventing a scope claim' {
        # A fail-closed run whose Privacy try threw before $results.PrivacyMode
        # was set still counts the complete Privacy inventory; the label names
        # only the missing profile evidence.
        $result = Get-PrivacyReportResultFixture -Mode $null -Total 119 -Passed 0 `
            -Failed 119 -NotChecked 0 -NotApplicable 0
        $output = Join-Path $TestDrive 'privacy-fail-closed-scope.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8

        $html | Should -Match '119 targets \(Privacy profile not proven\)'
        $html | Should -Not -Match 'maximum scope'
        $html | Should -Not -Match 'Privacy targets counted'
    }

    It 'shows a not-proven count as failed without a separate Privacy card' {
        $result = Get-PrivacyReportResultFixture -Mode Strict -Total 90 -Passed 53 `
            -Failed 0 -NotChecked 1 -NotApplicable 36
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

        $html | Should -Match '<div class="stat-value danger">1</div>'
        $html | Should -Match '<span>Failed:</span>\s*<strong>1</strong>'
        $html | Should -Match '<span class="status-badge failed"><span class="status-icon">&#10005;</span>Failed &middot; no saved choice</span>'
        $html | Should -Match '>By choice</button>'
        $html | Should -Not -MatchExactly 'No Saved Choice|NO SAVED CHOICE|nosavedchoice|progress-bar-segment unproven'
        $html | Should -Not -Match '<span class="badge '
        $html | Should -Not -Match '<section class="privacy-verdict'
        $html | Should -Not -Match '100% VERIFIED'
    }
}
