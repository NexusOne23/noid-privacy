<#
.SYNOPSIS
    Render the Verify-Complete-Hardening compliance results to an HTML report.

.DESCRIPTION
    Kept separate from Tools/Verify-Complete-Hardening.ps1 so the renderer can be
    unit-tested and changed without editing the verification logic.
#>

$notCheckedAccountingHelperPath = Join-Path $PSScriptRoot 'Get-VerificationNotCheckedAccounting.ps1'
if (-not (Test-Path -LiteralPath $notCheckedAccountingHelperPath -PathType Leaf)) {
    throw "Verification NotChecked accounting helper is missing: $notCheckedAccountingHelperPath"
}
. $notCheckedAccountingHelperPath

# Maps a UI culture to one of the report's text tables; anything else is English.
function Resolve-HardeningReportLanguage {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][string]$Language)

    if ([string]::IsNullOrWhiteSpace($Language)) { return 'en-US' }
    $value = $Language.Trim().ToLowerInvariant()
    if ($value -match '^zh(?:-|$)') {
        if ($value -match '(?:^|-)(?:hant|tw|hk|mo|cht)(?:-|$)') { return 'zh-TW' }
        return 'zh-CN'
    }
    switch ($value.Split('-')[0]) {
        'en' { return 'en-US' }
        'de' { return 'de-DE' }
        'fr' { return 'fr-FR' }
        'es' { return 'es-ES' }
        'it' { return 'it-IT' }
        'pt' { return 'pt-BR' }
        'ja' { return 'ja-JP' }
        'ru' { return 'ru-RU' }
        default { return 'en-US' }
    }
}

function New-HardeningHtmlReport {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([void])]
    param($Results, $OutputFile, [switch]$RedactComputerName, [string]$Language = 'en-US')

    if (-not $PSCmdlet.ShouldProcess($OutputFile, 'Write hardening HTML report')) {
        return
    }

    # One renderer for every language: display text comes from the text table,
    # numbers, element ids and the technical content of each row never change.
    $reportTextPath = Join-Path $PSScriptRoot 'HardeningReportText.json'
    $reportText = Get-Content -LiteralPath $reportTextPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $reportLanguage = Resolve-HardeningReportLanguage -Language $Language
    $fallbackText = $reportText.Languages.([string]$reportText.Fallback)
    $languageText = $reportText.Languages.$reportLanguage
    if ($null -eq $fallbackText) { throw 'Report text table has no fallback language' }
    $reportCultureInfo = [System.Globalization.CultureInfo]::GetCultureInfo($reportLanguage)
    # Static table text is trusted but still escaped; the middle dot keeps its
    # entity so the English report stays byte-identical to earlier builds.
    function ConvertTo-ReportText {
        param([AllowNull()][string]$Value)
        ([string]$Value).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace([string][char]0x00B7, '&middot;')
    }
    function Test-ReportText {
        param([string]$Key)
        ($null -ne $languageText -and $null -ne $languageText.PSObject.Properties[$Key]) -or
            $null -ne $fallbackText.PSObject.Properties[$Key]
    }
    # Plain table text for values that are encoded later with the row content.
    function Get-ReportPlainText {
        param([Parameter(Mandatory = $true)][string]$Key)
        if ($null -ne $languageText -and $null -ne $languageText.PSObject.Properties[$Key] -and
            -not [string]::IsNullOrEmpty([string]$languageText.$Key)) {
            return [string]$languageText.$Key
        }
        if ($null -eq $fallbackText.PSObject.Properties[$Key]) { throw "Report text key is missing: $Key" }
        return [string]$fallbackText.$Key
    }
    # Returns HTML: the escaped template filled with arguments the caller has
    # already encoded. A key missing in the language falls back to English.
    function Get-ReportText {
        param([Parameter(Mandatory = $true)][string]$Key, [object[]]$Arguments = @())
        $template = $null
        if ($null -ne $languageText -and $null -ne $languageText.PSObject.Properties[$Key]) {
            $template = [string]$languageText.$Key
        }
        if ([string]::IsNullOrEmpty($template)) {
            if ($null -eq $fallbackText.PSObject.Properties[$Key]) { throw "Report text key is missing: $Key" }
            $template = [string]$fallbackText.$Key
        }
        $encoded = ConvertTo-ReportText $template
        if (@($Arguments).Count -eq 0) { return $encoded }
        return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, $encoded, [object[]]@($Arguments))
    }

    # Calculate stats (use correct property names!)
    $totalSettings = $Results.TotalSettings
    $productTargetInventoryProperty = $Results.PSObject.Properties['ProductTargetInventory']
    $productTargetInventory = if ($null -ne $productTargetInventoryProperty) {
        [int]$productTargetInventoryProperty.Value
    }
    else { [int]$totalSettings }
    if ($productTargetInventory -lt [int]$totalSettings) {
        throw "Verification scope exceeds product inventory: scope=$totalSettings, inventory=$productTargetInventory"
    }
    $passedCount = $Results.Verified
    $failedCount = $Results.Failed
    $notCheckedCount = $Results.NotChecked
    $notApplicableCount = $Results.NotApplicable
    # Structured scalar disposition counts come from the verifier's hard
    # per-category weighted reconciliation. Older result objects fall back to
    # the legacy deliberate/unresolved split and remain fail-safe.
    $notCheckedDeliberateProperty = $Results.PSObject.Properties['NotCheckedDeliberate']
    $notCheckedDeliberateCount = if ($null -ne $notCheckedDeliberateProperty) { [int]$notCheckedDeliberateProperty.Value } else { 0 }
    $notCheckedNoSavedProperty = $Results.PSObject.Properties['NotCheckedNoSavedChoice']
    $notCheckedCannotProperty = $Results.PSObject.Properties['NotCheckedCannotVerify']
    $structuredDispositionCountsPresent = $null -ne $notCheckedNoSavedProperty -and $null -ne $notCheckedCannotProperty
    $notCheckedNoSavedCount = if ($structuredDispositionCountsPresent) { [int]$notCheckedNoSavedProperty.Value } else { 0 }
    $notCheckedCannotCount = if ($structuredDispositionCountsPresent) {
        [int]$notCheckedCannotProperty.Value
    }
    else { $notCheckedCount - $notCheckedDeliberateCount }
    if ($notCheckedDeliberateCount -lt 0 -or $notCheckedNoSavedCount -lt 0 -or $notCheckedCannotCount -lt 0 -or
        ($notCheckedDeliberateCount + $notCheckedNoSavedCount + $notCheckedCannotCount) -ne $notCheckedCount) {
        throw 'Verification NotChecked disposition totals do not reconcile for HTML rendering'
    }
    $notCheckedUnresolvedCount = $notCheckedNoSavedCount + $notCheckedCannotCount
    # One vocabulary on every surface: a required check that is not proven
    # is a failed check. Measured mismatches and missing evidence stay
    # separately counted; BY CHOICE and NOT APPLICABLE are never required.
    # The Failed card shows the total only; the mismatched / not proven split
    # is stated once, in the compliance line under the bar.
    $failedTotalCount = $failedCount + $notCheckedUnresolvedCount
    $requiredVerificationCount = $passedCount + $failedCount + $notCheckedUnresolvedCount
    $selectedModules = @($Results.SelectedModules)
    # The producer flags applied-scope runs explicitly; the module count is
    # only a fallback for older result objects without the property.
    $appliedScopeProperty = $Results.PSObject.Properties['AppliedScopeRun']
    $isAppliedScopeRun = if ($null -ne $appliedScopeProperty) { [bool]$appliedScopeProperty.Value } else { $selectedModules.Count -ne 7 }
    $reportScopeHtml = if (-not $isAppliedScopeRun) {
        Get-ReportText 'ScopeComplete'
    }
    else {
        $moduleNamesHtml = @($selectedModules | ForEach-Object {
                $moduleKey = 'Module_' + [string]$_
                if (Test-ReportText $moduleKey) { Get-ReportText $moduleKey }
                else { [System.Net.WebUtility]::HtmlEncode([string]$_) }
            }) -join (Get-ReportText 'ListSeparator')
        Get-ReportText 'ScopeAppliedFormat' @($moduleNamesHtml)
    }

    # The bar is the short human verdict, not a document-coverage meter.
    # NotApplicable and authoritatively deliberate exclusions are outside the
    # required verification denominator. Failed and unresolved NotChecked
    # targets remain in it, so an all-failed run is 0% rather than 100%.
    $invariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
    if ($requiredVerificationCount -gt 0) {
        $verificationPercent = [math]::Round(($passedCount / $requiredVerificationCount) * 100, 1)
        $verificationPercentText = Get-ReportText 'PercentFormat' @($verificationPercent.ToString('0.#', $reportCultureInfo))
        $passedBarWidth = (($passedCount / $requiredVerificationCount) * 100).ToString('0.####', $invariantCulture)
        $failedBarWidth = (($failedCount / $requiredVerificationCount) * 100).ToString('0.####', $invariantCulture)
        $notProvenBarWidth = (($notCheckedUnresolvedCount / $requiredVerificationCount) * 100).ToString('0.####', $invariantCulture)
        if ($failedTotalCount -gt 0) {
            $failedBreakdown = if ($failedCount -gt 0 -and $notCheckedUnresolvedCount -gt 0) {
                Get-ReportText 'FailedSplitFormat' @($failedCount, $notCheckedUnresolvedCount)
            }
            elseif ($notCheckedUnresolvedCount -gt 0) { Get-ReportText 'FailedNotProven' }
            else { '' }
            $complianceBarLabel = Get-ReportText 'BarPassedFailedFormat' @($verificationPercentText, $requiredVerificationCount, $failedTotalCount, $failedBreakdown)
        }
        else {
            $complianceBarLabel = Get-ReportText 'BarPassedFormat' @($verificationPercentText, $requiredVerificationCount)
        }
    }
    else {
        $passedBarWidth = '0'
        $failedBarWidth = '0'
        $notProvenBarWidth = '0'
        $complianceBarLabel = Get-ReportText 'BarNoTargets'
    }

    # The report is a compliance attestation and names its subject machine by
    # default so collected reports stay attributable. -RedactComputerName
    # produces the shareable variant; personal identities (SIDs, user profile
    # paths, e-mail addresses) are always redacted regardless.
    $computerNameHtml = if ($RedactComputerName) { Get-ReportText 'ComputerRedacted' } else { [System.Net.WebUtility]::HtmlEncode([string]$env:COMPUTERNAME) }
    $osInfo = Get-CimInstance Win32_OperatingSystem
    # ':' in a .NET custom format is the culture's time separator; keep the
    # documented yyyy-MM-dd HH:mm:ss form on every display language.
    $reportTimestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $versionFile = Join-Path $repoRoot 'VERSION'
    if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
        throw "Canonical VERSION file is missing: $versionFile"
    }
    $frameworkVersion = (Get-Content -LiteralPath $versionFile -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
    if ($frameworkVersion -notmatch '^\d+\.\d+\.\d+$') {
        throw "Canonical VERSION value is invalid: '$frameworkVersion'"
    }

    function ConvertTo-ReportHtml {
        param([AllowNull()][object]$Value)
        $text = [string]$Value
        $text = [regex]::Replace($text, '(?i)\bS-1-(?:5-21|12-1)-[0-9-]+\b', '[USER-SID]')
        # Consume the whole profile folder segment. \s in the class stopped at the
        # first space, so a stock 'C:\Users\John Doe' account leaked ' Doe\...'
        # into a report this function promises to redact - and exception messages
        # embedded verbatim in Actual cells carry full absolute paths.
        # The separator alternation also covers the JSON-escaped double-backslash
        # form (array/bare-scalar payloads render "C:\\Users\\John" verbatim) and
        # forward slashes from file URIs; quotes and line breaks terminate the
        # segment so a redaction never eats surrounding JSON structure or
        # spills onto the next line.
        $text = [regex]::Replace($text, '(?i)\b[A-Z]:(?:\\{1,2}|/)Users(?:\\{1,2}|/)[^\\/"''\r\n]+', '%USERPROFILE%')
        $text = [regex]::Replace($text, '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[EMAIL]')
        return [System.Net.WebUtility]::HtmlEncode($text)
    }
    # DISPLAY-ONLY transformation for the Expected/Actual value columns. The
    # verifier's result strings carry their comparison JSON verbatim
    # ({"Value":...} wrapper, one-of choice lists); those strings are contract
    # for the -ceq comparisons and stay untouched in the result objects. Only
    # the rendered cells unwrap them for readability:
    #   DWord/{"Value":1}                                -> DWord/1
    #   String/{"Value":"Block"}                         -> String/Block
    #   DWord/one-of [{"Value":1},{"Value":3}]           -> DWord/one-of [1 | 3]
    # Suffixes such as " (Apply choice unavailable)" survive unchanged. Only
    # the exact {"Value":<scalar>} pattern is transformed; array payloads
    # (MultiString/["a","b"]) and bare JSON scalars (ExpandString/"...")
    # pass through byte-for-byte.
    function Format-ReportValue {
        param([AllowNull()][object]$Value)
        $text = [string]$Value
        if ($text.IndexOf('{"Value":', [System.StringComparison]::Ordinal) -lt 0) { return $text }
        $scalarPattern = '(?:-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|"(?:[^"\\]|\\.)*")'
        $wrapperPattern = '\{"Value":' + $scalarPattern + '\}'
        $unwrapWrapper = {
            param([string]$JsonFragment)
            try {
                $payload = (ConvertFrom-Json -InputObject $JsonFragment -ErrorAction Stop).Value
                if ($null -eq $payload) { return 'null' }
                if ($payload -is [bool]) { return $payload.ToString().ToLowerInvariant() }
                return [string]$payload
            }
            catch { return $JsonFragment }
        }
        # Choice lists first: [{"Value":1},{"Value":3}] -> [1 | 3]
        $text = [regex]::Replace($text, ('\[' + $wrapperPattern + '(?:,' + $wrapperPattern + ')+\]'), {
                param($listMatch)
                $items = foreach ($itemMatch in [regex]::Matches($listMatch.Value, $wrapperPattern)) {
                    & $unwrapWrapper $itemMatch.Value
                }
                '[' + ($items -join ' | ') + ']'
            })
        # Remaining single wrappers: {"Value":1} -> 1, {"Value":"Block"} -> Block
        $text = [regex]::Replace($text, $wrapperPattern, { param($singleMatch) & $unwrapWrapper $singleMatch.Value })
        return $text
    }

    # Resolve raw ASR rule GUIDs in the Registry category to their documented
    # rule names. Source of truth is the ASR module's rule definition file; a
    # missing or unreadable file degrades to plain GUID display instead of
    # failing the report. The default hashtable comparer is case-insensitive,
    # matching the mixed-case GUIDs in the parsed baseline.
    $asrRuleFriendlyNames = @{}
    try {
        $asrRulesFile = Join-Path $repoRoot 'Modules\ASR\Config\ASR-Rules.json'
        # Assign first, then @(): in PowerShell 5.1 @(pipeline|ConvertFrom-Json)
        # would collect the emitted array as ONE element instead of enumerating.
        $asrRuleDefinitions = Get-Content -LiteralPath $asrRulesFile -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        foreach ($asrRuleDefinition in @($asrRuleDefinitions)) {
            if ($asrRuleDefinition.GUID -and $asrRuleDefinition.Name) {
                $asrRuleFriendlyNames[[string]$asrRuleDefinition.GUID] = [string]$asrRuleDefinition.Name
            }
        }
    }
    catch {
        $asrRuleFriendlyNames = @{}
    }

    # The Privacy scope is always its complete inventory; name the selected
    # profile next to the stable total, or say that no profile is proven.
    $privacyModeProperty = $Results.PSObject.Properties['PrivacyMode']
    $privacyCategoryPresent = @($Results.AllSettings | Where-Object {
            [string]$_.Category -ceq 'Privacy'
        }).Count -eq 1
    $privacyModeMeta = if ($null -ne $privacyModeProperty -and -not [string]::IsNullOrWhiteSpace([string]$privacyModeProperty.Value)) {
        $privacyModeKey = 'PrivacyMode_' + [string]$privacyModeProperty.Value
        $privacyModeHtml = if ([string]$privacyModeProperty.Value -cmatch '^[A-Za-z]+$' -and (Test-ReportText $privacyModeKey)) {
            Get-ReportText $privacyModeKey
        }
        else { [System.Net.WebUtility]::HtmlEncode([string]$privacyModeProperty.Value) }
        Get-ReportText 'PrivacyProfileFormat' @($privacyModeHtml)
    }
    elseif ($privacyCategoryPresent) {
        Get-ReportText 'PrivacyProfileNotProven'
    }
    else { '' }
    # OS Caption/BuildNumber are host-environment values (registry-backed) that
    # must be encoded before injection, exactly like every other rendered field,
    # so a tampered ProductName cannot inject markup into the shareable report.
    $osVersionHtml = Get-ReportText 'OsVersionFormat' @((ConvertTo-ReportHtml $osInfo.Caption), (ConvertTo-ReportHtml $osInfo.BuildNumber))

    # Consume the verifier's one observation; generating/printing a report
    # must not re-query the host or change the counted target inventory.
    $runtimeHtml = ''
    $runtimeProperty = $Results.PSObject.Properties['SecurityBaselineRuntime']
    if ($null -ne $runtimeProperty -and $null -ne $runtimeProperty.Value) {
        $runtime = $runtimeProperty.Value
        $runtimeHtml = '<section class="runtime-status" aria-labelledby="runtime-title"><h2 id="runtime-title">' + (Get-ReportText 'RuntimeTitle') + '</h2><dl>'
        foreach ($feature in $runtime.Features) {
            # Stable ids select the translated name and state; an observation
            # without them (older result objects) keeps its recorded text.
            $featureIdProperty = $feature.PSObject.Properties['Id']
            $labelIdProperty = $feature.PSObject.Properties['LabelId']
            $nameKey = if ($null -ne $featureIdProperty) { 'Runtime_' + [string]$featureIdProperty.Value } else { '' }
            $labelKey = if ($null -ne $labelIdProperty) { 'RuntimeState_' + [string]$labelIdProperty.Value } else { '' }
            $nameHtml = if ($nameKey -cmatch '^Runtime_[A-Za-z]+$' -and (Test-ReportText $nameKey)) { Get-ReportText $nameKey } else { ConvertTo-ReportHtml $feature.Name }
            $labelHtml = if ($labelKey -cmatch '^RuntimeState_[A-Za-z]+$' -and (Test-ReportText $labelKey)) { Get-ReportText $labelKey } else { ConvertTo-ReportHtml $feature.Label }
            $sourceHtml = ConvertTo-ReportHtml $feature.EvidenceSource
            $runtimeHtml += '<div><dt>{0}</dt><dd title="{2}">{1}</dd></div>' -f $nameHtml, $labelHtml, $sourceHtml
        }
        $noticeHtml = if ($null -ne $runtime.PSObject.Properties['NoticeId'] -and [string]$runtime.NoticeId -ceq 'RuntimeNotice') { Get-ReportText 'RuntimeNotice' } else { ConvertTo-ReportHtml $runtime.Notice }
        $runtimeHtml += '</dl><p>' + $noticeHtml + '</p>'
        if (@($runtime.Features | Where-Object { $_.State -notin @('Running','ProtectedAtBoot') }).Count -gt 0) {
            $guidanceHtml = if ($null -ne $runtime.PSObject.Properties['GuidanceId'] -and [string]$runtime.GuidanceId -ceq 'RuntimeGuidance') { Get-ReportText 'RuntimeGuidance' } else { ConvertTo-ReportHtml $runtime.Guidance }
            $runtimeHtml += '<p>' + $guidanceHtml + '</p>'
        }
        $runtimeHtml += '</section>'
    }

    # Build HTML
    $html = @"
<!DOCTYPE html>
<html lang="$(Get-ReportText 'HtmlLang')">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$(Get-ReportText 'DocumentTitleFormat' @($reportScopeHtml))</title>
<style>
    :root {
        --color-primary: #2563eb;
        --color-success: #10b981;
        --color-danger: #ef4444;
        --color-warning: #f59e0b;
        --color-bg-dark: #0f172a;
        --color-bg-light: #f8fafc;
        --color-text: #1e293b;
        --color-border: #e2e8f0;
    }

    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    .runtime-status { margin: 1rem 0; padding: 1rem; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; break-inside: avoid; }
    .runtime-status h2 { font-size: 1rem; margin-bottom: 0.6rem; }
    /* All protection features share one row on a desktop-width report;
       narrower windows and printed pages wrap to three, then two columns. */
    /* Each feature sits in its own equal-width tile, so the spacing between
       entries stays even regardless of how long a feature name is. */
    /* Equal tiles in one row; a tile never gets narrower than its text, which never wraps. */
    .runtime-status dl { display: grid; grid-auto-flow: column; grid-auto-columns: minmax(max-content, 1fr); gap: 0.5rem; }
    .runtime-status dl > div { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 0.5rem 0.75rem; }
    @media (max-width: 1100px) { .runtime-status dl { grid-auto-flow: row; grid-template-columns: repeat(3, minmax(max-content, 1fr)); } }
    @media (max-width: 640px) { .runtime-status dl { grid-template-columns: repeat(2, minmax(max-content, 1fr)); } }
    .runtime-status dt { font-size: 0.8rem; color: #475569; white-space: nowrap; }
    .runtime-status dd { font-size: 0.9rem; font-weight: 600; white-space: nowrap; }
    .runtime-status p { margin-top: 0.6rem; font-size: 0.8rem; color: #475569; }

    body {
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        min-height: 100vh;
    }

    .container {
        max-width: 1400px;
        margin: 0 auto;
        background: white;
        border-radius: 20px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        overflow: hidden;
    }

    .header {
        background: linear-gradient(135deg, var(--color-bg-dark) 0%, #1e3a8a 100%);
        color: white;
        padding: 3rem;
        text-align: center;
        position: relative;
        overflow: hidden;
    }

    .header::before {
        content: '';
        position: absolute;
        top: -50%;
        right: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
        animation: pulse 15s ease-in-out infinite;
    }

    @keyframes pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.1); }
    }

    .header h1 {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
        position: relative;
        z-index: 1;
    }

    .header .subtitle {
        font-size: 1.1rem;
        opacity: 0.9;
        position: relative;
        z-index: 1;
    }

    .meta-info {
        background: var(--color-bg-light);
        padding: 2rem;
        border-bottom: 3px solid var(--color-border);
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 1.5rem;
    }

    .meta-item {
        display: flex;
        flex-direction: column;
    }

    .meta-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #64748b;
        margin-bottom: 0.25rem;
    }

    .meta-value {
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--color-text);
    }

    .dashboard {
        padding: 2rem 2rem 1rem;
        background: white;
    }

    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1.5rem;
        margin-bottom: 1.75rem;
    }

    .stat-card {
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 4px solid var(--color-primary);
        transition: transform 0.2s, box-shadow 0.2s;
    }

    .stat-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    }

    .stat-card.success { border-left-color: var(--color-success); }
    .stat-card.danger { border-left-color: var(--color-danger); }
    .stat-card.warning { border-left-color: var(--color-warning); }
    .stat-card.neutral { border-left-color: #64748b; }
    .stat-card.choice { border-left-color: #6366f1; }

    .stat-value {
        font-size: 2.5rem;
        font-weight: 700;
        line-height: 1;
        margin-bottom: 0.5rem;
    }

    .stat-value.success { color: var(--color-success); }
    .stat-value.danger { color: var(--color-danger); }
    .stat-value.warning { color: var(--color-warning); }
    .stat-value.neutral { color: #475569; }
    .stat-value.choice { color: #6366f1; }

    .stat-label {
        font-size: 0.875rem;
        color: #64748b;
        font-weight: 500;
    }

    .progress-section {
        margin: 0 0 1.75rem;
    }

    .progress-bar-container {
        background: #e2e8f0;
        height: 50px;
        border-radius: 25px;
        overflow: hidden;
        position: relative;
        display: flex;
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
    }

    .progress-bar-segment {
        height: 100%;
        flex: 0 0 auto;
        transition: width 0.6s ease;
        position: relative;
        overflow: hidden;
    }

    .progress-bar-segment.passed {
        background: linear-gradient(90deg, var(--color-success) 0%, #34d399 100%);
    }

    .progress-bar-segment.failed {
        background: linear-gradient(90deg, var(--color-danger) 0%, #f87171 100%);
    }

    /* Not proven is a failed check whose evidence is missing: the failed
       colour, hatched so the cause stays visible without a legend. */
    .progress-bar-segment.notproven {
        background: repeating-linear-gradient(135deg, #ef4444 0, #ef4444 8px, #f87171 8px, #f87171 16px);
    }

    /* The label spans the whole track instead of living inside the fill, so it
       stays fully visible at low compliance percentages (narrow fill). */
    .progress-bar-label {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 2;
        pointer-events: none;
    }

    .progress-bar-label span {
        background: rgba(255,255,255,0.92);
        color: #1e293b;
        font-weight: 700;
        font-size: 1rem;
        padding: 0.3rem 1.1rem;
        border-radius: 999px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.15);
        white-space: nowrap;
        max-width: calc(100% - 1rem);
        overflow: hidden;
        text-overflow: ellipsis;
    }

    .controls {
        display: flex;
        gap: 1rem;
        margin-bottom: 0;
        flex-wrap: wrap;
    }

    .modules-container {
        padding: 0 2rem 1rem;
    }

    .search-box {
        flex: 1;
        min-width: 300px;
        padding: 0.75rem 1rem;
        border: 2px solid var(--color-border);
        border-radius: 8px;
        font-size: 1rem;
        transition: border-color 0.2s;
    }

    .search-box:focus {
        outline: none;
        border-color: var(--color-primary);
    }

    .filter-buttons {
        display: flex;
        gap: 0.5rem;
    }

    .btn {
        padding: 0.75rem 1.5rem;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
        font-size: 0.875rem;
    }

    .btn-primary {
        background: var(--color-primary);
        color: white;
    }

    .btn-success {
        background: var(--color-success);
        color: white;
    }

    .btn-danger {
        background: var(--color-danger);
        color: white;
    }

    .btn-choice {
        background: #6366f1;
        color: white;
    }

    .btn-neutral {
        background: #64748b;
        color: white;
    }

    .btn:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }

    .btn.active {
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
    }

    .module-section {
        margin: 1rem 0;
        border: 2px solid var(--color-border);
        border-radius: 12px;
        overflow: hidden;
        background: white;
    }

    .module-header {
        background: linear-gradient(135deg, var(--color-bg-dark) 0%, #334155 100%);
        color: white;
        padding: 1.5rem;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
        transition: background 0.2s;
    }

    .module-header:hover {
        background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%);
    }

    .module-title {
        font-size: 1.25rem;
        font-weight: 700;
        display: flex;
        align-items: center;
        gap: 1rem;
    }

    .module-stats {
        display: flex;
        gap: 1.5rem;
        font-size: 0.875rem;
    }

    .module-stat {
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .expand-icon {
        transition: transform 0.3s;
    }

    .module-section.collapsed .expand-icon {
        transform: rotate(-90deg);
    }

    /* Expanded content keeps overflow: visible so the sticky table header can
       stick; the collapsed state must clip via overflow: hidden, otherwise
       max-height: 0 hides nothing. max-height none<->0 is not animatable, so
       no transition is declared (the expand icon keeps its own animation). */
    .module-content {
        max-height: none;
        overflow: visible;
    }

    .module-section.collapsed .module-content {
        max-height: 0;
        overflow: hidden;
    }

    .settings-table {
        width: 100%;
        border-collapse: collapse;
        table-layout: fixed;
    }

    .settings-table thead {
        background: var(--color-bg-light);
        position: sticky;
        top: 0;
        z-index: 10;
    }

    .settings-table th {
        padding: 1rem;
        text-align: left;
        font-weight: 600;
        color: var(--color-text);
        border-bottom: 2px solid var(--color-border);
        font-size: 0.875rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .settings-table th:nth-child(1) { width: 25%; }
    .settings-table th:nth-child(2) { width: 30%; }
    .settings-table th:nth-child(3) { width: 15%; }
    .settings-table th:nth-child(4) { width: 15%; }
    .settings-table th:nth-child(5) { width: 15%; }

    .settings-table td {
        padding: 1rem;
        border-bottom: 1px solid var(--color-border);
        word-wrap: break-word;
        word-break: break-word;
        overflow-wrap: break-word;
    }

    .settings-table td:nth-child(2),
    .settings-table td:nth-child(3),
    .settings-table td:nth-child(4) {
        font-size: 0.8rem;
    }

    .settings-table tbody tr {
        transition: background 0.2s;
    }

    .settings-table tbody tr:hover {
        background: #f1f5f9;
    }

    .settings-table tbody tr.passed {
        background: rgba(16, 185, 129, 0.05);
    }

    .settings-table tbody tr.failed {
        background: rgba(239, 68, 68, 0.05);
    }

    .settings-table tbody tr.bychoice {
        background: rgba(99, 102, 241, 0.06);
    }

    .settings-table tbody tr.notapplicable {
        background: rgba(100, 116, 139, 0.08);
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.375rem 0.75rem;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .status-badge.passed {
        background: #d1fae5;
        color: #065f46;
    }

    .status-badge.failed {
        background: #fee2e2;
        color: #991b1b;
    }

    .status-badge.bychoice {
        background: #e0e7ff;
        color: #3730a3;
    }

    .status-badge.notapplicable {
        background: #e2e8f0;
        color: #334155;
    }

    .status-icon {
        font-size: 1rem;
    }

    .value-cell {
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.875rem;
    }

    .value-match {
        color: var(--color-success);
        font-weight: 600;
    }

    .value-mismatch {
        color: var(--color-danger);
        font-weight: 600;
    }

    .export-section {
        padding: 2rem;
        background: var(--color-bg-light);
        border-top: 2px solid var(--color-border);
        display: flex;
        gap: 1rem;
        justify-content: center;
        flex-wrap: wrap;
    }

    .footer {
        background: var(--color-bg-dark);
        color: rgba(255,255,255,0.7);
        padding: 2rem;
        text-align: center;
    }

    .footer a {
        color: var(--color-primary);
        text-decoration: none;
    }

    @page {
        size: landscape;
        margin: 1cm;
    }

    @media print {
        * {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
        }
        body {
            background: white;
            padding: 0;
        }
        .container {
            box-shadow: none;
            border-radius: 0;
        }
        .controls, .export-section, .filter-empty {
            display: none;
        }
        /* Balanced header for print */
        .header {
            padding: 1.5rem 2rem;
            page-break-inside: avoid;
        }
        .header h1 {
            font-size: 1.8rem;
            margin-bottom: 0.3rem;
        }
        .header .subtitle {
            font-size: 1rem;
        }
        /* Balanced meta-info for print */
        .meta-info {
            padding: 1rem 1.5rem;
            gap: 1rem;
            page-break-inside: avoid;
        }
        .meta-label {
            font-size: 0.65rem;
        }
        .meta-value {
            font-size: 0.95rem;
        }
        /* Balanced dashboard for print */
        .dashboard {
            padding: 1rem 1.5rem 0.75rem;
            page-break-inside: avoid;
        }
        .stats-grid {
            page-break-inside: avoid;
            display: flex;
            flex-wrap: nowrap;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        .stat-card {
            flex: 1;
            min-width: 0;
            padding: 1rem;
            page-break-inside: avoid;
            box-shadow: none;
        }
        .stat-value {
            font-size: 2rem;
        }
        .stat-label {
            font-size: 0.75rem;
        }
        .progress-section {
            margin: 0;
            page-break-inside: avoid;
        }
        .progress-bar-container {
            height: 40px;
        }
        .progress-bar-segment.passed { background: #10b981 !important; }
        .progress-bar-segment.failed { background: #ef4444 !important; }
        .progress-bar-segment.notproven { background: #f87171 !important; }
        .modules-container {
            padding: 0 1.5rem 0.75rem;
        }
        .module-section {
            margin: 0.75rem 0;
            page-break-inside: auto;
            break-inside: auto;
        }
        .module-header {
            padding: 0.75rem 1rem;
            page-break-after: avoid;
            break-after: avoid-page;
        }
        .module-title {
            font-size: 1rem;
            gap: 0.5rem;
        }
        .module-stats {
            gap: 0.75rem;
            font-size: 0.7rem;
        }
        .expand-icon {
            display: none;
        }
        .module-content,
        .module-section.collapsed .module-content {
            display: block !important;
            max-height: none !important;
            overflow: visible !important;
        }
        html[data-print-mode="summary"] .module-section {
            page-break-inside: avoid;
            break-inside: avoid;
            margin: 0.3rem 0;
        }
        html[data-print-mode="summary"] .module-header {
            page-break-after: auto;
            break-after: auto;
            padding: 0.45rem 0.75rem;
        }
        html[data-print-mode="summary"] .header {
            padding: 1rem 1.5rem;
        }
        html[data-print-mode="summary"] .header h1 {
            font-size: 1.55rem;
        }
        html[data-print-mode="summary"] .header .subtitle {
            font-size: 0.85rem;
        }
        html[data-print-mode="summary"] .meta-info {
            grid-template-columns: repeat(4, minmax(0, 1fr));
            padding: 0.65rem 1.25rem;
            gap: 0.75rem;
        }
        html[data-print-mode="summary"] .meta-label {
            font-size: 0.55rem;
        }
        html[data-print-mode="summary"] .meta-value {
            font-size: 0.75rem;
        }
        html[data-print-mode="summary"] .dashboard {
            padding: 0.65rem 1.25rem 0.45rem;
        }
        html[data-print-mode="summary"] .stats-grid {
            gap: 0.6rem;
            margin-bottom: 0.55rem;
        }
        html[data-print-mode="summary"] .stat-card {
            padding: 0.55rem 0.75rem;
        }
        html[data-print-mode="summary"] .stat-value {
            font-size: 1.5rem;
            margin-bottom: 0.25rem;
        }
        html[data-print-mode="summary"] .stat-label {
            font-size: 0.6rem;
        }
        html[data-print-mode="summary"] .progress-bar-container {
            height: 30px;
        }
        html[data-print-mode="summary"] .progress-bar-label {
            font-size: 0.75rem;
        }
        html[data-print-mode="summary"] .modules-container {
            padding: 0 1.25rem 0.4rem;
        }
        html[data-print-mode="summary"] .module-title {
            font-size: 0.8rem;
        }
        html[data-print-mode="summary"] .module-stats {
            gap: 0.5rem;
            font-size: 0.55rem;
        }
        html[data-print-mode="summary"] .module-content,
        html[data-print-mode="summary"] .module-section.collapsed .module-content {
            display: none !important;
        }
        html[data-print-mode="detailed"] .module-content,
        html[data-print-mode="detailed"] .module-section.collapsed .module-content {
            display: block !important;
            max-height: none !important;
            overflow: visible !important;
        }
        .settings-table {
            font-size: 0.7rem;
            page-break-inside: auto;
        }
        .settings-table thead {
            display: table-header-group;
            position: static;
        }
        .settings-table tr {
            /* Search and status filters set inline display:none on screen.
               A complete printout must include those rows too. */
            display: table-row !important;
            page-break-inside: avoid;
            break-inside: avoid;
        }
        .settings-table th {
            padding: 0.55rem;
        }
        .settings-table td {
            padding: 0.5rem;
        }
        .settings-table td:nth-child(2),
        .settings-table td:nth-child(3),
        .settings-table td:nth-child(4) {
            font-size: 0.65rem;
        }
        .settings-table th:nth-child(1) { width: 22%; }
        .settings-table th:nth-child(2) { width: 33%; }
        .settings-table th:nth-child(3) { width: 15%; }
        .settings-table th:nth-child(4) { width: 15%; }
        .settings-table th:nth-child(5) { width: 15%; }
        .footer {
            padding: 0.35rem 1rem;
            font-size: 0.65rem;
            line-height: 1.2;
            white-space: nowrap;
            page-break-inside: avoid;
        }
        .footer p {
            display: inline;
        }
        .footer p + p::before {
            content: ' \0000b7  ';
        }
    }

    @media (max-width: 768px) {
        .stats-grid {
            grid-template-columns: 1fr;
        }
        .controls {
            flex-direction: column;
        }
        .search-box {
            width: 100%;
        }
    }
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>NoID Privacy v$frameworkVersion</h1>
        <p class="subtitle">$reportScopeHtml</p>
    </div>

    <div class="meta-info">
        <div class="meta-item">
            <span class="meta-label">$(Get-ReportText 'MetaGenerated')</span>
            <span class="meta-value">$reportTimestamp</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">$(Get-ReportText 'MetaComputer')</span>
            <span class="meta-value">$computerNameHtml</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">$(Get-ReportText 'MetaOs')</span>
            <span class="meta-value">$osVersionHtml</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">$(Get-ReportText 'MetaScope')</span>
            <span class="meta-value">$(Get-ReportText 'MetaScopeTargetsFormat' @($totalSettings, $privacyModeMeta))</span>
        </div>
    </div>

    <div class="dashboard">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">$totalSettings</div>
                <div class="stat-label">$(Get-ReportText 'StatScope')</div>
            </div>
            <div class="stat-card success">
                <div class="stat-value success">$passedCount</div>
                <div class="stat-label">$(Get-ReportText 'StatPassed')</div>
            </div>
            <div class="stat-card danger">
                <div class="stat-value danger">$failedTotalCount</div>
                <div class="stat-label">$(Get-ReportText 'StatFailed')</div>
            </div>
            <div class="stat-card choice">
                <div class="stat-value choice">$notCheckedDeliberateCount</div>
                <div class="stat-label">$(Get-ReportText 'StatByChoice')</div>
            </div>
            <div class="stat-card neutral">
                <div class="stat-value neutral">$notApplicableCount</div>
                <div class="stat-label">$(Get-ReportText 'StatNotApplicable')</div>
            </div>
        </div>

        <div class="progress-section">
            <div class="progress-bar-container">
                <div class="progress-bar-segment passed" style="width: $passedBarWidth%;"></div>
                <div class="progress-bar-segment failed" style="width: $failedBarWidth%;"></div>
                <div class="progress-bar-segment notproven" style="width: $notProvenBarWidth%;"></div>
                <div class="progress-bar-label"><span>$complianceBarLabel</span></div>
            </div>
        </div>

        $runtimeHtml

        <div class="controls">
            <input type="text" class="search-box" id="searchBox" placeholder="$(Get-ReportText 'SearchPlaceholder')">
            <div class="filter-buttons">
                <button class="btn btn-primary active" onclick="filterSettings('all', this)">$(Get-ReportText 'FilterAll')</button>
                <button class="btn btn-success" onclick="filterSettings('passed', this)">$(Get-ReportText 'FilterPassed')</button>
                <button class="btn btn-danger" onclick="filterSettings('failed', this)">$(Get-ReportText 'FilterFailed')</button>
                <button class="btn btn-choice" onclick="filterSettings('bychoice', this)">$(Get-ReportText 'FilterByChoice')</button>
                <button class="btn btn-neutral" onclick="filterSettings('notapplicable', this)">$(Get-ReportText 'FilterNotApplicable')</button>
            </div>
        </div>
    </div>

    <div class="modules-container" id="modulesContainer">
        <p class="filter-empty" id="filterEmpty" role="status" hidden>$(Get-ReportText 'FilterEmpty')</p>
"@

    # Build module sections with details (iterate over ALL modules)
    foreach ($category in $Results.AllSettings) {
        $categoryName = [string]$category.Category
        # The name becomes an element id, a JavaScript string argument and
        # visible text. HTML encoding alone cannot make a JavaScript literal
        # safe, so only plain identifiers (the verifier's fixed names) render.
        if ($categoryName -cnotmatch '^[A-Za-z][A-Za-z0-9]*$') {
            throw "Verification category name is not a plain identifier: '$categoryName'"
        }
        $catTotal = $category.Total
        $catPassed = $category.Passed
        $catFailed = $category.Failed
        $catNotChecked = if ($category.PSObject.Properties['NotChecked']) { [int]$category.NotChecked } else { 0 }
        $catNotApplicable = if ($category.PSObject.Properties['NotApplicable']) { [int]$category.NotApplicable } else { 0 }
        $catNotCheckedDetails = @($category.NotCheckedDetails)
        $catNotCheckedAccounting = Get-VerificationNotCheckedAccounting `
            -Details $catNotCheckedDetails -ExpectedCount $catNotChecked `
            -Context "HTML category '$categoryName'"
        # Same vocabulary as the summary cards: not-proven targets count as
        # failed, authoritative user choices as BY CHOICE.
        $catByChoice = [int]$catNotCheckedAccounting.ByChoice
        $catFailedTotal = [int]$catFailed + ($catNotChecked - $catByChoice)
        $categoryTitleHtml = if (Test-ReportText ('Category_' + $categoryName)) { Get-ReportText ('Category_' + $categoryName) } else { $categoryName }

        $html += @"
        <div class="module-section" id="module-$categoryName">
            <div class="module-header" onclick="toggleModule('module-$categoryName')">
                <div class="module-title">
                    <span class="expand-icon">&#9660;</span>
                    <span>$categoryTitleHtml</span>
                </div>
                <div class="module-stats">
                    <span class="module-stat">
                        <span>$(Get-ReportText 'ModuleTotal')</span>
                        <strong>$catTotal</strong>
                    </span>
                    <span class="module-stat" style="color: #10b981;">
                        <span>$(Get-ReportText 'ModulePassed')</span>
                        <strong>$catPassed</strong>
                    </span>
                    <span class="module-stat" style="color: #ef4444;">
                        <span>$(Get-ReportText 'ModuleFailed')</span>
                        <strong>$catFailedTotal</strong>
                    </span>
                    <span class="module-stat" style="color: #6366f1;">
                        <span>$(Get-ReportText 'ModuleByChoice')</span>
                        <strong>$catByChoice</strong>
                    </span>
                    <span class="module-stat" style="color: #cbd5e1;">
                        <span>$(Get-ReportText 'ModuleNotApplicable')</span>
                        <strong>$catNotApplicable</strong>
                    </span>
                </div>
            </div>
            <div class="module-content">
                <table class="settings-table">
                    <thead>
                        <tr>
                            <th>$(Get-ReportText 'ColumnSetting')</th>
                            <th>$(Get-ReportText 'ColumnPath')</th>
                            <th>$(Get-ReportText 'ColumnExpected')</th>
                            <th>$(Get-ReportText 'ColumnActual')</th>
                            <th>$(Get-ReportText 'ColumnStatus')</th>
                        </tr>
                    </thead>
                    <tbody>
"@

        # Add rows for PASSED settings (detailed view)
        foreach ($detail in $category.PassedDetails) {
            $rowClass = 'passed'
            $statusBadge = '<span class="status-badge passed"><span class="status-icon">&#10003;</span>' + (Get-ReportText 'BadgePassed') + '</span>'

            # Extract setting info based on category (both producer spellings
            # accepted, same as the FailedDetails branch below)
            if ($categoryName -eq "RegistryPolicies" -or $categoryName -eq "Registry") {
                $settingName = if ($detail.Name) { $detail.Name } else { $detail.ValueName }
                $pathInfo = if ($detail.Path) { $detail.Path } else { $detail.KeyName }
                $expected = $detail.Expected
                $actual = $detail.Actual

                # Improve cryptic setting names
                if ($settingName -match '^\*\*del') {
                    $settingName = "[GPO Cleanup] Remove obsolete values from: $($pathInfo -replace '.*\\', '')"
                }
                elseif ($settingName -eq "(Reserved)") {
                    $settingName = "[IE Security] Reserved Entry (System-level protection)"
                }
                elseif ($settingName -eq "1" -and $pathInfo -like "*DeviceClasses*") {
                    $settingName = "USB Storage Devices Block (GUID {d48179be-ec20-11d1-b6b8-00c04fa372a7})"
                }
                elseif ($settingName -eq "1" -and $pathInfo -like "*ExtensionInstallBlocklist*") {
                    $settingName = "[Edge] Block all extensions by default (wildcard)"
                }
                elseif ($settingName -match "^[0-9A-F]{4}$" -and $pathInfo -like "*Internet Settings*Zones*") {
                    # Internet Explorer Zone Settings - Hex to readable
                    # Names follow Microsoft's documented URL action values
                    # (KB182569 / urlmon URLACTION_* / inetres.admx policy
                    # names for the post-KB actions 120b/120c/140C/270C).
                    $zoneSettingNames = @{
                        "1C00" = "Java Permissions"
                        "270C" = "Antimalware Scanning of ActiveX Controls"
                        "1201" = "Initialize & Script ActiveX Not Marked Safe"
                        "2001" = "Run .NET Components Signed with Authenticode"
                        "2102" = "Script-Initiated Windows Without Constraints"
                        "1802" = "Drag & Drop or Copy & Paste Files"
                        "160A" = "Include Local Directory Path on Upload"
                        "1406" = "Access Data Sources Across Domains"
                        "1804" = "Launching Programs & Files in an IFRAME"
                        "2200" = "Automatic Prompting for File Downloads"
                        "1209" = "Allow Scriptlets"
                        "1206" = "Scripting of IE Web Browser Control"
                        "1809" = "Use Pop-up Blocker"
                        "2500" = "Protected Mode"
                        "2103" = "Allow Status Bar Updates via Script"
                        "1606" = "Userdata Persistence"
                        "2402" = ".NET: Loose XAML"
                        "2004" = "Run .NET Components Not Signed with Authenticode"
                        "1001" = "Download Signed ActiveX Controls"
                        "1A00" = "Logon Options"
                        "2708" = "Drag Content Between Domains (Same Window)"
                        "1004" = "Download Unsigned ActiveX Controls"
                        "120b" = "Approved-Domains-Only ActiveX Without Prompt"
                        "1407" = "Programmatic Clipboard Access"
                        "1409" = "Cross-Site Scripting (XSS) Filter"
                        "1607" = "Navigate Windows & Frames Across Domains"
                        "2709" = "Drag Content Between Domains (Separate Windows)"
                        "2101" = "Websites in Less Privileged Zones Navigate into Zone"
                        "2301" = "Use SmartScreen Filter"
                        "1806" = "Launching Applications & Unsafe Files"
                        "120c" = "Approved-Domains-Only TDC ActiveX Control"
                        "140C" = "Allow VBScript to Run in IE"
                        "1608" = "Allow META REFRESH"
                        "1200" = "Run ActiveX Controls & Plugins"
                        "1400" = "Active Scripting"
                        "1402" = "Scripting of Java Applets"
                        "1803" = "File Downloads"
                        "2000" = "Binary & Script Behaviors"
                        "1405" = "Script ActiveX Marked Safe for Scripting"
                    }
                    $friendlyName = $zoneSettingNames[$settingName]
                    if ($friendlyName) {
                        $zoneName = if ($pathInfo -like "*Zones\0*") { "My Computer" }
                        elseif ($pathInfo -like "*Zones\1*") { "Local Intranet" }
                        elseif ($pathInfo -like "*Zones\2*") { "Trusted Sites" }
                        elseif ($pathInfo -like "*Zones\3*") { "Internet" }
                        elseif ($pathInfo -like "*Zones\4*") { "Restricted Sites" }
                        else { "Zone" }
                        $settingName = "[$zoneName] $friendlyName"
                    }
                }
                elseif ($settingName -match '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -and $pathInfo -like "*Exploit Guard\ASR\Rules*") {
                    # ASR rules are stored as raw GUID value names; render the
                    # documented rule name with the GUID kept for traceability.
                    $asrRuleFriendlyName = $asrRuleFriendlyNames[$settingName]
                    if ($asrRuleFriendlyName) {
                        $settingName = "$asrRuleFriendlyName ($settingName)"
                    }
                }
                elseif ($settingName -eq "DCSettingIndex") {
                    $settingName = "Power Setting (On Battery/DC)"
                }
                elseif ($settingName -eq "ACSettingIndex") {
                    $settingName = "Power Setting (Plugged In/AC)"
                }
                elseif (($settingName -eq "iexplore.exe" -or $settingName -eq "explorer.exe") -and $pathInfo -like "*FeatureControl*") {
                    # IE FeatureControl settings
                    $featureNames = @{
                        "FEATURE_DISABLE_MK_PROTOCOL"     = "Disable MK Protocol (Security)"
                        "FEATURE_MIME_HANDLING"           = "MIME Handling Security"
                        "FEATURE_MIME_SNIFFING"           = "MIME Sniffing Protection"
                        "FEATURE_RESTRICT_ACTIVEXINSTALL" = "Restrict ActiveX Install"
                        "FEATURE_RESTRICT_FILEDOWNLOAD"   = "Restrict File Download"
                        "FEATURE_SECURITYBAND"            = "Security Band (Info Bar)"
                        "FEATURE_WINDOW_RESTRICTIONS"     = "Window Restrictions (Pop-up Block)"
                        "FEATURE_ZONE_ELEVATION"          = "Zone Elevation Block"
                    }
                    $processName = if ($settingName -eq "iexplore.exe") { "IE" } else { "Explorer" }
                    foreach ($feature in $featureNames.Keys) {
                        if ($pathInfo -like "*$feature*") {
                            $settingName = "[$processName] $($featureNames[$feature])"
                            break
                        }
                    }
                }
            }
            elseif ($categoryName -eq "SecurityTemplate") {
                $settingName = $detail.Setting
                $pathInfo = Get-ReportPlainText 'PathSecurityTemplate'
                $expected = $detail.Expected
                $actual = $detail.Actual
            }
            elseif ($categoryName -eq "AuditPolicies") {
                $settingName = $detail.Policy
                $pathInfo = Get-ReportPlainText 'PathAuditPolicy'
                $expected = $detail.Expected
                $actual = $detail.Actual
            }
            elseif ($categoryName -eq "ASR") {
                $settingName = $detail.Rule
                $pathInfo = Get-ReportPlainText 'PathAsrRule'
                $expected = $detail.Expected
                $actual = $detail.Actual
            }
            else {
                # Generic handling for other categories
                $settingName = if ($detail.Setting) { $detail.Setting } elseif ($detail.Check) { $detail.Check } elseif ($detail.Policy) { $detail.Policy } else { Get-ReportPlainText 'SettingUnknown' }
                $pathInfo = if ($detail.Path) { $detail.Path } else { $categoryName }
                $expected = $detail.Expected
                $actual = $detail.Actual

                # EdgeHardening specific improvements
                if ($categoryName -eq "EdgeHardening") {
                    if ($settingName -match '^\*\*delvals') {
                        $settingName = "[Edge] GPO Cleanup - Remove obsolete policy values"
                    }
                    elseif ($settingName -eq "1") {
                        # Check if path contains ExtensionInstallBlocklist
                        if ($detail.Path -like "*ExtensionInstallBlocklist*") {
                            $settingName = "[Edge] Block all extensions by default (wildcard *)"
                        }
                    }
                }
            }

            # Unwrap comparison JSON for display, then encode HTML special characters
            $settingName = ConvertTo-ReportHtml $settingName
            $pathInfo = ConvertTo-ReportHtml $pathInfo
            $expected = ConvertTo-ReportHtml (Format-ReportValue $expected)
            $actual = ConvertTo-ReportHtml (Format-ReportValue $actual)

            $html += @"
                        <tr class="$rowClass">
                            <td title="$settingName">$settingName</td>
                            <td class="value-cell" title="$pathInfo">$pathInfo</td>
                            <td class="value-cell" title="$expected">$expected</td>
                            <td class="value-cell" title="$actual">$actual</td>
                            <td>$statusBadge</td>
                        </tr>
"@
        }

        # Add rows for FAILED settings (detailed view)
        foreach ($detail in $category.FailedDetails) {
            $rowClass = 'failed'
            $statusBadge = '<span class="status-badge failed"><span class="status-icon">&#10005;</span>' + (Get-ReportText 'BadgeFailed') + '</span>'

            # Extract setting info based on category
            if ($categoryName -eq "RegistryPolicies" -or $categoryName -eq "Registry") {
                $settingName = if ($detail.ValueName) { $detail.ValueName } elseif ($detail.Name) { $detail.Name } else { Get-ReportPlainText 'SettingUnknown' }
                $pathInfo = if ($detail.KeyName) { $detail.KeyName } elseif ($detail.Path) { $detail.Path } else { Get-ReportPlainText 'SettingUnknown' }
                $expected = $detail.Expected
                $actual = $detail.Actual

                # Improve cryptic setting names (same logic as passed details)
                if ($settingName -match '^\*\*del') {
                    $settingName = "[GPO Cleanup] Remove obsolete values from: $($pathInfo -replace '.*\\', '')"
                }
                elseif ($settingName -eq "(Reserved)") {
                    $settingName = "[IE Security] Reserved Entry (System-level protection)"
                }
                elseif ($settingName -eq "1" -and $pathInfo -like "*DeviceClasses*") {
                    $settingName = "USB Storage Devices Block (GUID {d48179be-ec20-11d1-b6b8-00c04fa372a7})"
                }
                elseif ($settingName -eq "1" -and $pathInfo -like "*ExtensionInstallBlocklist*") {
                    $settingName = "[Edge] Block all extensions by default (wildcard)"
                }
                elseif ($settingName -match "^[0-9A-F]{4}$" -and $pathInfo -like "*Internet Settings*Zones*") {
                    # Internet Explorer Zone Settings - Hex to readable
                    # Names follow Microsoft's documented URL action values
                    # (KB182569 / urlmon URLACTION_* / inetres.admx policy
                    # names for the post-KB actions 120b/120c/140C/270C).
                    $zoneSettingNames = @{
                        "1C00" = "Java Permissions"
                        "270C" = "Antimalware Scanning of ActiveX Controls"
                        "1201" = "Initialize & Script ActiveX Not Marked Safe"
                        "2001" = "Run .NET Components Signed with Authenticode"
                        "2102" = "Script-Initiated Windows Without Constraints"
                        "1802" = "Drag & Drop or Copy & Paste Files"
                        "160A" = "Include Local Directory Path on Upload"
                        "1406" = "Access Data Sources Across Domains"
                        "1804" = "Launching Programs & Files in an IFRAME"
                        "2200" = "Automatic Prompting for File Downloads"
                        "1209" = "Allow Scriptlets"
                        "1206" = "Scripting of IE Web Browser Control"
                        "1809" = "Use Pop-up Blocker"
                        "2500" = "Protected Mode"
                        "2103" = "Allow Status Bar Updates via Script"
                        "1606" = "Userdata Persistence"
                        "2402" = ".NET: Loose XAML"
                        "2004" = "Run .NET Components Not Signed with Authenticode"
                        "1001" = "Download Signed ActiveX Controls"
                        "1A00" = "Logon Options"
                        "2708" = "Drag Content Between Domains (Same Window)"
                        "1004" = "Download Unsigned ActiveX Controls"
                        "120b" = "Approved-Domains-Only ActiveX Without Prompt"
                        "1407" = "Programmatic Clipboard Access"
                        "1409" = "Cross-Site Scripting (XSS) Filter"
                        "1607" = "Navigate Windows & Frames Across Domains"
                        "2709" = "Drag Content Between Domains (Separate Windows)"
                        "2101" = "Websites in Less Privileged Zones Navigate into Zone"
                        "2301" = "Use SmartScreen Filter"
                        "1806" = "Launching Applications & Unsafe Files"
                        "120c" = "Approved-Domains-Only TDC ActiveX Control"
                        "140C" = "Allow VBScript to Run in IE"
                        "1608" = "Allow META REFRESH"
                        "1200" = "Run ActiveX Controls & Plugins"
                        "1400" = "Active Scripting"
                        "1402" = "Scripting of Java Applets"
                        "1803" = "File Downloads"
                        "2000" = "Binary & Script Behaviors"
                        "1405" = "Script ActiveX Marked Safe for Scripting"
                    }
                    $friendlyName = $zoneSettingNames[$settingName]
                    if ($friendlyName) {
                        $zoneName = if ($pathInfo -like "*Zones\0*") { "My Computer" }
                        elseif ($pathInfo -like "*Zones\1*") { "Local Intranet" }
                        elseif ($pathInfo -like "*Zones\2*") { "Trusted Sites" }
                        elseif ($pathInfo -like "*Zones\3*") { "Internet" }
                        elseif ($pathInfo -like "*Zones\4*") { "Restricted Sites" }
                        else { "Zone" }
                        $settingName = "[$zoneName] $friendlyName"
                    }
                }
                elseif ($settingName -match '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -and $pathInfo -like "*Exploit Guard\ASR\Rules*") {
                    # ASR rules are stored as raw GUID value names; render the
                    # documented rule name with the GUID kept for traceability.
                    $asrRuleFriendlyName = $asrRuleFriendlyNames[$settingName]
                    if ($asrRuleFriendlyName) {
                        $settingName = "$asrRuleFriendlyName ($settingName)"
                    }
                }
                elseif ($settingName -eq "DCSettingIndex") {
                    $settingName = "Power Setting (On Battery/DC)"
                }
                elseif ($settingName -eq "ACSettingIndex") {
                    $settingName = "Power Setting (Plugged In/AC)"
                }
                elseif (($settingName -eq "iexplore.exe" -or $settingName -eq "explorer.exe") -and $pathInfo -like "*FeatureControl*") {
                    # IE FeatureControl settings
                    $featureNames = @{
                        "FEATURE_DISABLE_MK_PROTOCOL"     = "Disable MK Protocol (Security)"
                        "FEATURE_MIME_HANDLING"           = "MIME Handling Security"
                        "FEATURE_MIME_SNIFFING"           = "MIME Sniffing Protection"
                        "FEATURE_RESTRICT_ACTIVEXINSTALL" = "Restrict ActiveX Install"
                        "FEATURE_RESTRICT_FILEDOWNLOAD"   = "Restrict File Download"
                        "FEATURE_SECURITYBAND"            = "Security Band (Info Bar)"
                        "FEATURE_WINDOW_RESTRICTIONS"     = "Window Restrictions (Pop-up Block)"
                        "FEATURE_ZONE_ELEVATION"          = "Zone Elevation Block"
                    }
                    $processName = if ($settingName -eq "iexplore.exe") { "IE" } else { "Explorer" }
                    foreach ($feature in $featureNames.Keys) {
                        if ($pathInfo -like "*$feature*") {
                            $settingName = "[$processName] $($featureNames[$feature])"
                            break
                        }
                    }
                }
            }
            elseif ($categoryName -eq "SecurityTemplate") {
                $settingName = $detail.Setting
                $pathInfo = Get-ReportPlainText 'PathSecurityTemplate'
                $expected = $detail.Expected
                $actual = $detail.Actual
            }
            elseif ($categoryName -eq "AuditPolicies") {
                $settingName = $detail.Policy
                $pathInfo = Get-ReportPlainText 'PathAuditPolicy'
                $expected = $detail.Expected
                $actual = $detail.Actual
            }
            elseif ($categoryName -eq "ASR") {
                $settingName = $detail.Rule
                $pathInfo = Get-ReportPlainText 'PathAsrRule'
                $expected = $detail.Expected
                $actual = $detail.Actual
            }
            else {
                # Generic handling for other categories
                $settingName = if ($detail.Setting) { $detail.Setting } elseif ($detail.Check) { $detail.Check } elseif ($detail.Policy) { $detail.Policy } else { Get-ReportPlainText 'SettingUnknown' }
                $pathInfo = if ($detail.Path) { $detail.Path } else { $categoryName }
                $expected = $detail.Expected
                $actual = $detail.Actual

                # EdgeHardening specific improvements
                if ($categoryName -eq "EdgeHardening") {
                    if ($settingName -match '^\*\*delvals') {
                        $settingName = "[Edge] GPO Cleanup - Remove obsolete policy values"
                    }
                    elseif ($settingName -eq "1") {
                        # Check if path contains ExtensionInstallBlocklist
                        if ($detail.Path -like "*ExtensionInstallBlocklist*") {
                            $settingName = "[Edge] Block all extensions by default (wildcard *)"
                        }
                    }
                }
            }

            # Unwrap comparison JSON for display, then encode HTML special characters
            $settingName = ConvertTo-ReportHtml $settingName
            $pathInfo = ConvertTo-ReportHtml $pathInfo
            $expected = ConvertTo-ReportHtml (Format-ReportValue $expected)
            $actual = ConvertTo-ReportHtml (Format-ReportValue $actual)

            # Every FailedDetails row is a mismatch by construction (no detail
            # object carries a Status property), so the Actual cell states it
            # directly instead of through a conditional that always chose it.
            $html += @"
                        <tr class="$rowClass">
                            <td title="$settingName">$settingName</td>
                            <td class="value-cell" title="$pathInfo">$pathInfo</td>
                            <td class="value-cell" title="$expected">$expected</td>
                            <td class="value-cell value-mismatch" title="$actual">$actual</td>
                            <td>$statusBadge</td>
                        </tr>
"@
        }

        # NotChecked remains one machine state. Its verifier-owned disposition
        # tells people whether it is missing evidence or a proven user choice.
        foreach ($detail in @($category.NotCheckedDetails)) {
            $settingName = if ($detail.Setting) { $detail.Setting } elseif ($detail.Rule) { $detail.Rule } elseif ($detail.Check) { $detail.Check } elseif ($detail.Policy) { $detail.Policy } else { Get-ReportPlainText 'SettingDeclaredCheck' }
            $expected = $detail.Expected
            $actual = $detail.Actual
            $settingName = ConvertTo-ReportHtml $settingName
            # A missing Path used to repeat the module name; an em dash marks
            # "no path" honestly (entity injected after encoding on purpose).
            $pathInfo = if ($detail.Path) { ConvertTo-ReportHtml $detail.Path } else { '&#8212;' }
            $expected = ConvertTo-ReportHtml (Format-ReportValue $expected)
            $actual = ConvertTo-ReportHtml (Format-ReportValue $actual)
            $dispositionProperty = $detail.PSObject.Properties['VerificationDisposition']
            if ($null -eq $dispositionProperty) {
                throw "HTML category '$categoryName' contains a NotChecked row without VerificationDisposition"
            }
            $disposition = [string]$dispositionProperty.Value
            $affectedTargetCount = [int]$detail.AffectedTargetCount
            $reasonCode = ConvertTo-ReportHtml ([string]$detail.VerificationReasonCode)
            $evidenceSource = ConvertTo-ReportHtml ([string]$detail.VerificationEvidenceSource)
            # A user choice is BY CHOICE; missing evidence is a failed check
            # whose badge names the cause (no saved choice / not readable).
            $statusBadgeClass = switch ($disposition) {
                'ByChoice' { 'bychoice' }
                'NoSavedChoice' { 'failed' }
                'CannotVerify' { 'failed' }
                default { throw "HTML category '$categoryName' contains invalid NotChecked disposition '$disposition'" }
            }
            $rowClass = if ($disposition -ceq 'ByChoice') { 'bychoice' } else { 'failed notproven' }
            $statusBadgeText = switch ($disposition) {
                'ByChoice' { Get-ReportText 'BadgeByChoice' }
                'NoSavedChoice' { Get-ReportText 'BadgeFailedNoSavedChoice' }
                'CannotVerify' { Get-ReportText 'BadgeFailedNotReadable' }
            }
            # Failed keeps the failed cross; a user's own choice gets a neutral
            # mark instead of an alert sign.
            $statusIcon = if ($disposition -ceq 'ByChoice') { '&#9675;' } else { '&#10005;' }
            if ($affectedTargetCount -gt 1) {
                $statusBadgeText += Get-ReportText 'BadgeTargetsFormat' @($affectedTargetCount)
            }
            $html += @"
                        <tr class="$rowClass" data-verification-reason="$reasonCode" data-evidence-source="$evidenceSource">
                            <td title="$settingName">$settingName</td>
                            <td class="value-cell" title="$pathInfo">$pathInfo</td>
                            <td class="value-cell" title="$expected">$expected</td>
                            <td class="value-cell" title="$actual">$actual</td>
                            <td><span class="status-badge $statusBadgeClass"><span class="status-icon">$statusIcon</span>$statusBadgeText</span></td>
                        </tr>
"@
        }

        # NotApplicable is a declared target outside this host's supported scope.
        foreach ($detail in @($category.NotApplicableDetails)) {
            $settingName = if ($detail.Setting) { $detail.Setting } elseif ($detail.Rule) { $detail.Rule } elseif ($detail.Check) { $detail.Check } elseif ($detail.Policy) { $detail.Policy } else { Get-ReportPlainText 'SettingDeclaredCheck' }
            $pathInfo = if ($detail.Path) { $detail.Path } else { $categoryName }
            $expected = $detail.Expected
            $actual = $detail.Actual
            $settingName = ConvertTo-ReportHtml $settingName
            $pathInfo = ConvertTo-ReportHtml $pathInfo
            $expected = ConvertTo-ReportHtml (Format-ReportValue $expected)
            $actual = ConvertTo-ReportHtml (Format-ReportValue $actual)
            $html += @"
                        <tr class="notapplicable">
                            <td title="$settingName">$settingName</td>
                            <td class="value-cell" title="$pathInfo">$pathInfo</td>
                            <td class="value-cell" title="$expected">$expected</td>
                            <td class="value-cell" title="$actual">$actual</td>
                            <td><span class="status-badge notapplicable"><span class="status-icon">-</span>$(Get-ReportText 'BadgeNotApplicable')</span></td>
                        </tr>
"@
        }

        # A category without any result rows gets one explanatory row
        if ($catFailed -eq 0 -and $catPassed -eq 0 -and $catNotChecked -eq 0 -and $catNotApplicable -eq 0) {
            $html += @"
                        <tr>
                            <td colspan="5" style="padding: 2rem; text-align: center; color: #64748b;">
                                $(Get-ReportText 'ModuleEmpty')
                            </td>
                        </tr>
"@
        }

        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
"@
    }

    # Close HTML
    $html += @"
    </div>

    <div class="export-section">
        <button class="btn btn-primary" onclick="printReport('summary')">$(Get-ReportText 'PrintSummary')</button>
        <button class="btn btn-primary" onclick="printReport('detailed')">$(Get-ReportText 'PrintDetailed')</button>
    </div>

    <div class="footer">
        <p>$(Get-ReportText 'FooterGeneratedFormat' @($frameworkVersion))</p>
        <p>$(Get-ReportText 'FooterTagline')</p>
    </div>
</div>

<script>
    // One shared visibility pass combines the active state filter with the
    // search term, so neither control clobbers the other.
    let activeFilter = 'all';
    const collapsedBeforeFiltering = new Map();

    function applyFilters() {
        const searchTerm = document.getElementById('searchBox').value.trim().toLowerCase();
        const filtering = activeFilter !== 'all' || searchTerm !== '';
        let anyMatch = false;
        document.querySelectorAll('.module-section').forEach(section => {
            let sectionMatches = false;
            section.querySelectorAll('.settings-table tbody tr').forEach(row => {
                const matchesFilter = activeFilter === 'all' || row.classList.contains(activeFilter);
                const matchesSearch = searchTerm === '' || row.textContent.toLowerCase().includes(searchTerm);
                const matches = matchesFilter && matchesSearch;
                row.style.display = matches ? '' : 'none';
                sectionMatches = sectionMatches || matches;
            });
            anyMatch = anyMatch || sectionMatches;
            // Reveal matching evidence even when its section was collapsed.
            // Clearing both controls restores the reader's original layout.
            if (filtering) {
                if (!collapsedBeforeFiltering.has(section)) {
                    collapsedBeforeFiltering.set(section, section.classList.contains('collapsed'));
                }
                section.classList.toggle('collapsed', !sectionMatches);
            } else if (collapsedBeforeFiltering.has(section)) {
                section.classList.toggle('collapsed', collapsedBeforeFiltering.get(section));
                collapsedBeforeFiltering.delete(section);
            }
        });
        document.getElementById('filterEmpty').hidden = !filtering || anyMatch;
    }

    document.getElementById('searchBox').addEventListener('input', applyFilters);

    // The clicked button arrives as an explicit parameter (the deprecated
    // global `event` is gone).
    function filterSettings(filter, sourceButton) {
        activeFilter = filter;
        const buttons = document.querySelectorAll('.filter-buttons .btn');
        buttons.forEach(btn => btn.classList.remove('active'));
        sourceButton.classList.add('active');
        applyFilters();
    }

    function toggleModule(moduleId) {
        const section = document.getElementById(moduleId);
        section.classList.toggle('collapsed');
    }

    function clearPrintMode() {
        document.documentElement.removeAttribute('data-print-mode');
    }

    // Printing is deterministic and never mutates the on-screen collapse
    // state. Summary prints module counters only; detailed prints every row.
    function printReport(mode) {
        if (mode !== 'summary' && mode !== 'detailed') {
            throw new Error('Unsupported print mode');
        }
        document.documentElement.setAttribute('data-print-mode', mode);
        window.addEventListener('afterprint', clearPrintMode, { once: true });
        window.print();
    }

    document.addEventListener('DOMContentLoaded', function() {
        const modules = document.querySelectorAll('.module-section');
        modules.forEach((module, index) => {
            if (index > 0) {
                module.classList.add('collapsed');
            }
        });
    });
</script>
</body>
</html>
"@

    # Save HTML file via .NET WriteAllText with UTF-8 NO-BOM. Browsers tolerate BOM
    # but text-diff tools / CI lint / report-aggregators expect canonical UTF-8.
    $htmlEncoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($OutputFile, $html, $htmlEncoding)
}
