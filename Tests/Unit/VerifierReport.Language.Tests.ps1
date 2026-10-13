#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $script:RepoRoot 'Tools/Private/Get-VerificationNotCheckedAccounting.ps1')
    . (Join-Path $script:RepoRoot 'Tools/Private/New-HardeningHtmlReport.ps1')
    $script:ReportText = Get-Content (Join-Path $script:RepoRoot 'Tools/Private/HardeningReportText.json') -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $script:Languages = @('en-US','de-DE','fr-FR','es-ES','it-IT','pt-BR','ja-JP','ru-RU','zh-CN','zh-TW')

    function Get-NotCheckedRow {
        param([string]$Disposition, [int]$Count = 1)
        [PSCustomObject]@{
            Setting="NotChecked $Disposition"; Path='HKLM:\SOFTWARE\Test'
            Expected='DWord/{"Value":1}'; Actual='No saved choice'
            CheckState='NotChecked'; VerificationDisposition=$Disposition
            VerificationEvidenceSource=$(switch ($Disposition) { 'ByChoice' { 'ApplyIntent' } 'NoSavedChoice' { 'None' } default { 'RuntimeQuery' } })
            VerificationReasonCode="Test.$Disposition"
            AffectedTargetCount=$Count
        }
    }

    # Every row kind and both runtime paths, so the structure comparison covers the whole report.
    function Get-LanguageReportFixture {
        $registry = [PSCustomObject]@{
            Category='Registry'; Total=5; Passed=3; Failed=1; NotChecked=0; NotApplicable=1
            PassedDetails=@(
                [PSCustomObject]@{ Name='NoLMHash'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Expected='DWord/{"Value":1}'; Actual='DWord/{"Value":1}' }
                [PSCustomObject]@{ Name='AllowTelemetry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Expected='DWord/{"Value":0}'; Actual='DWord/{"Value":0}' }
                [PSCustomObject]@{ Name='EnableSmartScreen'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Expected='DWord/{"Value":1}'; Actual='DWord/{"Value":1}' }
            )
            FailedDetails=@([PSCustomObject]@{ ValueName='RequireSecuritySignature'; KeyName='HKLM:\SYSTEM\X'; Expected='DWord/{"Value":1}'; Actual='DWord/{"Value":0}' })
            NotCheckedDetails=@()
            NotApplicableDetails=@([PSCustomObject]@{ Setting='Enterprise-only value'; Path='HKLM:\SOFTWARE\Y'; Expected='DWord/1'; Actual='Enterprise only' })
        }
        $template = [PSCustomObject]@{
            Category='SecurityTemplate'; Total=1; Passed=1; Failed=0; NotChecked=0; NotApplicable=0
            PassedDetails=@([PSCustomObject]@{ Setting='MinimumPasswordLength'; Expected='14'; Actual='14' })
            FailedDetails=@(); NotCheckedDetails=@(); NotApplicableDetails=@()
        }
        $asr = [PSCustomObject]@{
            Category='ASR'; Total=3; Passed=0; Failed=0; NotChecked=3; NotApplicable=0
            PassedDetails=@(); FailedDetails=@()
            NotCheckedDetails=@((Get-NotCheckedRow 'NoSavedChoice' 2), (Get-NotCheckedRow 'CannotVerify'))
            NotApplicableDetails=@()
        }
        $privacy = [PSCustomObject]@{
            Category='Privacy'; Total=5; Passed=1; Failed=0; NotChecked=4; NotApplicable=0
            PassedDetails=@([PSCustomObject]@{ Setting='Readable Privacy evidence'; Path='HKLM:\SOFTWARE\Z'; Expected='DWord/1'; Actual='DWord/1' })
            FailedDetails=@(); NotCheckedDetails=@((Get-NotCheckedRow 'ByChoice' 4)); NotApplicableDetails=@()
        }
        $empty = [PSCustomObject]@{
            Category='DNS'; Total=0; Passed=0; Failed=0; NotChecked=0; NotApplicable=0
            PassedDetails=@(); FailedDetails=@(); NotCheckedDetails=@(); NotApplicableDetails=@()
        }
        [PSCustomObject]@{
            SelectedModules=@('SecurityBaseline','ASR','DNS','Privacy','AntiAI','EdgeHardening','AdvancedSecurity')
            TotalSettings=14; ProductTargetInventory=703; Verified=5; Failed=1
            NotChecked=7; NotCheckedDeliberate=4; NotCheckedNoSavedChoice=2; NotCheckedCannotVerify=1
            NotApplicable=1; AppliedScopeRun=$false; PrivacyMode='Strict'
            AllSettings=@($registry, $template, $asr, $privacy, $empty)
            SecurityBaselineRuntime=[PSCustomObject]@{
                Features=@(
                    [PSCustomObject]@{ Id='VBS'; Name='VBS'; State='NotRunning'; Label='Enabled, not running'; LabelId='EnabledNotRunning'; EvidenceSource='Win32_DeviceGuard' }
                    [PSCustomObject]@{ Id='HVCI'; Name='Memory integrity (HVCI)'; State='Running'; Label='Running'; LabelId='Running'; EvidenceSource='Win32_DeviceGuard' }
                    [PSCustomObject]@{ Id='LSA'; Name='LSA protection'; State='ProtectedAtBoot'; Label='Protected at this boot'; LabelId='ProtectedAtBoot'; EvidenceSource='CurrentBootWinInit12' }
                )
                Notice='Passed policy checks confirm configuration; runtime protection is shown separately.'
                NoticeId='RuntimeNotice'
                Guidance='For newly applied protection, restart Windows and verify again. If it remains inactive, check hardware, drivers and Windows edition requirements.'
                GuidanceId='RuntimeGuidance'
            }
        }
    }

    function Get-ReportHtml {
        param([AllowNull()][string]$Language, [switch]$Default)
        $output = Join-Path $TestDrive ("report-" + [Guid]::NewGuid().ToString('N') + '.html')
        if ($Default) { New-HardeningHtmlReport -Results (Get-LanguageReportFixture) -OutputFile $output -RedactComputerName }
        else { New-HardeningHtmlReport -Results (Get-LanguageReportFixture) -OutputFile $output -RedactComputerName -Language $Language }
        # The generation time is the only value allowed to differ between two renders.
        (Get-Content -LiteralPath $output -Raw -Encoding UTF8) -replace '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', 'TIMESTAMP'
    }

    # Everything that is not display text: tags with their attributes, numbers in the counters, row classes.
    function Get-ReportStructure {
        param([string]$Html)
        $tags = [regex]::Matches($Html, '<[a-z][^>]*>') | ForEach-Object {
            $_.Value -replace '(?:placeholder|title|lang)="[^"]*"', 'TEXT'
        }
        $numbers = [regex]::Matches($Html, '<(?:strong|div class="stat-value[^"]*")>(\d+)</') | ForEach-Object { $_.Groups[1].Value }
        @($tags) + '--' + @($numbers)
    }
}

Describe 'HTML report languages' {
    BeforeEach {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption='Microsoft Windows 11 Pro'; BuildNumber='26300' } }
    }

    It 'ships one complete text table per GUI language with matching placeholders' {
        @($script:ReportText.Languages.PSObject.Properties.Name | Sort-Object) | Should -Be @($script:Languages | Sort-Object)
        $english = $script:ReportText.Languages.'en-US'
        $keys = @($english.PSObject.Properties.Name | Sort-Object)
        foreach ($language in $script:Languages) {
            $table = $script:ReportText.Languages.$language
            @($table.PSObject.Properties.Name | Sort-Object) | Should -Be $keys -Because $language
            foreach ($key in $keys) {
                [string]$table.$key | Should -Not -BeNullOrEmpty -Because "$language $key"
                @([regex]::Matches([string]$table.$key, '\{\d\}') | ForEach-Object Value | Sort-Object) |
                    Should -Be @([regex]::Matches([string]$english.$key, '\{\d\}') | ForEach-Object Value | Sort-Object) -Because "$language $key"
            }
        }
    }

    It 'maps <Value> to <Expected>' -TestCases @(
        @{ Value='de'; Expected='de-DE' }, @{ Value='DE-AT'; Expected='de-DE' }, @{ Value='pt-PT'; Expected='pt-BR' }
        @{ Value='zh-Hans'; Expected='zh-CN' }, @{ Value='zh-SG'; Expected='zh-CN' }, @{ Value='zh-Hant'; Expected='zh-TW' }
        @{ Value='zh-HK'; Expected='zh-TW' }, @{ Value='ja-JP'; Expected='ja-JP' }, @{ Value='xx-YY'; Expected='en-US' }
        @{ Value=''; Expected='en-US' }
    ) {
        param($Value, $Expected)
        Resolve-HardeningReportLanguage -Language $Value | Should -BeExactly $Expected
    }

    It 'keeps numbers, rows and element structure identical in every language' {
        $englishStructure = Get-ReportStructure (Get-ReportHtml -Language 'en-US')
        foreach ($language in $script:Languages) {
            $structure = Get-ReportStructure (Get-ReportHtml -Language $language)
            ($structure -join "`n") | Should -BeExactly ($englishStructure -join "`n") -Because $language
        }
    }

    It 'writes <Language> with its own words and no English interface text' -TestCases @(
        @{ Language='de-DE' }, @{ Language='fr-FR' }, @{ Language='es-ES' }, @{ Language='it-IT' }, @{ Language='pt-BR' }
        @{ Language='ja-JP' }, @{ Language='ru-RU' }, @{ Language='zh-CN' }, @{ Language='zh-TW' }
    ) {
        param($Language)
        $html = Get-ReportHtml -Language $Language
        $table = $script:ReportText.Languages.$Language
        $html | Should -Match ('<html lang="' + [regex]::Escape([string]$table.HtmlLang) + '">')
        foreach ($key in @('StatPassed','StatByChoice','ColumnExpected','RuntimeTitle','PrintSummary','Category_Privacy','RuntimeState_EnabledNotRunning')) {
            $expectedText = ([string]$table.$key).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace([string][char]0x00B7, '&middot;')
            $html | Should -Match ([regex]::Escape($expectedText)) -Because $key
        }
        # English phrase -> its key; a phrase is a leak only where the language uses other words.
        $englishPhrases = [ordered]@{
            'Verification Scope'='StatScope'; 'required checks passed'='BarPassedFormat'; 'Print Summary'='PrintSummary'
            'Search settings'='SearchPlaceholder'; 'Windows protection at verification'='RuntimeTitle'; '>Passed<'='StatPassed'
            '>Failed<'='StatFailed'; 'By choice'='BadgeByChoice'; 'Not applicable'='BadgeNotApplicable'; 'Total:'='ModuleTotal'
            'No settings configured'='ModuleEmpty'; 'Report Generated'='MetaGenerated'; 'Enabled, not running'='RuntimeState_EnabledNotRunning'
        }
        foreach ($english in $englishPhrases.Keys) {
            if (('>' + [string]$table.($englishPhrases[$english]) + '<') -like ('*' + $english + '*')) { continue }
            $html | Should -Not -Match ([regex]::Escape($english)) -Because "$Language must not show '$english'"
        }
        # Technical row content stays as Windows names it.
        $html | Should -Match 'RequireSecuritySignature'
        $html | Should -Match 'MinimumPasswordLength'
    }

    It 'formats the percentage the way <Language> writes it' -TestCases @(
        @{ Language='en-US'; Expected='55.6% of 9' }, @{ Language='de-DE'; Expected='55,6' + [char]0x00A0 + '% der erforderlichen Pr' + [char]0x00FC + 'fungen (insgesamt 9)' }
        @{ Language='fr-FR'; Expected='55,6' + [char]0x202F + '% des v' + [char]0x00E9 + 'rifications requises (9 au total)' }, @{ Language='ja-JP'; Expected='9 ' + [char]0x4EF6 + [char]0x4E2D + ' 55.6%' }
        @{ Language='ru-RU'; Expected='55,6' + [char]0x00A0 + '% ' }, @{ Language='zh-CN'; Expected=' 9 ' + [char]0x9879 + [char]0xFF0C + [char]0x901A + [char]0x8FC7 + [char]0x7387 + ' 55.6%' }
    ) {
        param($Language, $Expected)
        Get-ReportHtml -Language $Language | Should -Match ([regex]::Escape($Expected))
    }

    It 'renders English by default and for an unsupported language' {
        $english = Get-ReportHtml -Language 'en-US'
        Get-ReportHtml -Default | Should -BeExactly $english
        Get-ReportHtml -Language 'xx-YY' | Should -BeExactly $english
        $english | Should -Match '<html lang="en">'
        $english | Should -Match '55\.6% of 9 required checks passed &middot; 4 failed \(1 mismatched, 3 not proven\)'
        $english | Should -Match 'Security Baseline &middot; Registry policies'
    }

    It 'keeps the recorded runtime text of an observation without stable ids' {
        $result = Get-LanguageReportFixture
        $result.SecurityBaselineRuntime.Features[0].PSObject.Properties.Remove('Id')
        $result.SecurityBaselineRuntime.Features[0].PSObject.Properties.Remove('LabelId')
        $output = Join-Path $TestDrive 'legacy-runtime.html'
        New-HardeningHtmlReport -Results $result -OutputFile $output -RedactComputerName -Language 'de-DE'
        $html = Get-Content -LiteralPath $output -Raw -Encoding UTF8
        $html | Should -Match '<dt>VBS</dt><dd title="Win32_DeviceGuard">Enabled, not running</dd>'
        $html | Should -Match ('<dt>Speicherintegrit' + [char]0x00E4 + 't \(HVCI\)</dt><dd title="Win32_DeviceGuard">Wird ausgef' + [char]0x00FC + 'hrt</dd>')
    }
}
