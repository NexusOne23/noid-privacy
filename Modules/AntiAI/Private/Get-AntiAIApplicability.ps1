#Requires -Version 5.1

function Get-AntiAIApplicability {
    <#
    .SYNOPSIS
        Reports OS/edition applicability separately from registry write success.

    .DESCRIPTION
        A policy value can be written and read back even when the installed
        Windows edition, servicing level, or app version ignores it. This
        helper keeps that distinction visible to callers. It does not turn an
        edition-limited or preview policy into a false runtime-success claim.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if (Get-Command Get-WindowsVersion -ErrorAction SilentlyContinue) {
        $windows = Get-WindowsVersion
    }
    else {
        $versionKey = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $build = [int]$versionKey.GetValue('CurrentBuildNumber', $os.BuildNumber)
        $ubr = [int]$versionKey.GetValue('UBR', 0)
        $displayVersion = [string]$versionKey.GetValue('DisplayVersion', '')
        $edition = [string]$versionKey.GetValue('EditionID', '')
        $installationType = [string]$versionKey.GetValue('InstallationType', '')
        $isClient = ([int]$os.ProductType -eq 1 -and $installationType -notmatch '(?i)Server')
        $release = 'Unknown'
        $supportLevel = 'Unsupported'

        if ($isClient -and $displayVersion -eq '24H2' -and $build -ge 26100 -and $build -lt 26200) {
            $release = '24H2'; $supportLevel = 'Stable'
        }
        elseif ($isClient -and $displayVersion -eq '25H2' -and $build -ge 26200 -and $build -lt 26300) {
            $release = '25H2'; $supportLevel = 'Stable'
        }
        elseif ($isClient -and $displayVersion -eq '26H2' -and $build -ge 26300 -and $build -lt 28000) {
            $release = '26H2'; $supportLevel = 'Experimental'
        }
        elseif ($isClient -and [string]::IsNullOrWhiteSpace($displayVersion)) {
            if ($build -ge 26100 -and $build -lt 26200) { $release = '24H2'; $supportLevel = 'Stable' }
            elseif ($build -ge 26200 -and $build -lt 26300) { $release = '25H2'; $supportLevel = 'Stable' }
        }

        $windows = [PSCustomObject]@{
            Release        = $release
            DisplayVersion = $displayVersion
            BuildNumber    = $build
            UpdateBuildRevision = $ubr
            FullBuild      = "$build.$ubr"
            Edition        = $edition
            IsClient       = $isClient
            IsSupported    = ($supportLevel -in @('Stable', 'Experimental'))
            SupportLevel   = $supportLevel
        }
    }

    # OperatingSystemSKU is the documented, language-independent GetProductInfo
    # signal and correctly classifies evaluation editions (for example
    # EnterpriseEval). EditionID remains a fallback for future/unknown SKUs.
    $sku = [int]$os.OperatingSystemSKU
    $editionId = [string]$windows.Edition
    $homeSkus = @(2, 3, 5, 26, 98, 99, 100, 101)
    $professionalSkus = @(6, 16, 48, 49, 103, 161, 162, 164)
    $enterpriseSkus = @(4, 27, 70, 72, 84, 125, 126, 129, 130, 175)
    $educationSkus = @(121, 122)
    $iotEnterpriseSkus = @(188, 191)
    $editionFamily = if ($sku -in $homeSkus) { 'Home' }
        elseif ($sku -in $professionalSkus) { 'Professional' }
        elseif ($sku -in $enterpriseSkus) { 'Enterprise' }
        elseif ($sku -in $educationSkus) { 'Education' }
        elseif ($sku -in $iotEnterpriseSkus) { 'IoTEnterprise' }
        elseif ($editionId -match '^Core') { 'Home' }
        elseif ($editionId -match '^Professional') { 'Professional' }
        elseif ($editionId -match '^Enterprise') { 'Enterprise' }
        elseif ($editionId -match '^Education') { 'Education' }
        elseif ($editionId -match '^IoTEnterprise') { 'IoTEnterprise' }
        else { 'Unknown' }
    if ($editionFamily -eq 'Unknown') {
        throw "Unsupported or unknown AntiAI edition applicability: SKU=$sku, EditionID='$editionId'"
    }
    $commercialEdition = $editionFamily -in @('Enterprise', 'Education', 'IoTEnterprise')
    $proOrHigherEdition = $editionFamily -in @('Professional', 'Enterprise', 'Education', 'IoTEnterprise')
    $warnings = [System.Collections.Generic.List[string]]::new()
    # Pure edition/geography applicability facts belong here: they are already
    # reported per target as NotApplicable during verification, so they must not
    # inflate the module warning count. Real protection-gap disclosures
    # (unsupported profile, servicing floor, Copilot MSIX limits) stay warnings.
    $applicabilityNotes = [System.Collections.Generic.List[string]]::new()
    $insiderEnrollment = $false
    $insiderEvidence = [System.Collections.Generic.List[string]]::new()
    if ($windows.SupportLevel -eq 'Experimental' -and $windows.Release -eq '26H2') {
        $insiderEnrollment = $true
        $insiderEvidence.Add('Explicitly recognized 26H2 Experimental Preview DisplayVersion/build profile (not runtime-validated or release-approved)')
    }
    $selfHostSelectionPath = 'HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Selection'
    if (Test-Path -LiteralPath $selfHostSelectionPath -PathType Container -ErrorAction Stop) {
        $selection = Get-Item -LiteralPath $selfHostSelectionPath -ErrorAction Stop
        $selectionValues = @{}
        foreach ($name in @('UIBranch', 'UIContentType', 'UIRing')) {
            if ($selection.GetValueNames() -contains $name) {
                $selectionValues[$name] = [string]$selection.GetValue($name)
            }
        }
        if ($selectionValues.Count -gt 0 -and
            (@($selectionValues.Values | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0)) {
            $insiderEnrollment = $true
            $insiderEvidence.Add('WindowsSelfHost enrollment: ' + (($selectionValues.GetEnumerator() |
                        Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '))
        }
    }

    if (-not $windows.IsSupported) {
        $warnings.Add("Unsupported Windows client profile: DisplayVersion='$($windows.DisplayVersion)', build=$($windows.FullBuild), edition='$($windows.Edition)'")
    }
    if ($windows.SupportLevel -eq 'Experimental') {
        $warnings.Add('Windows 11 26H2 is recognized only as an Experimental Preview and is currently not runtime-validated or release-approved; Insider-only WindowsAI policies and their behavior can change')
    }
    if (-not $commercialEdition) {
        $applicabilityNotes.Add("Edition '$($windows.Edition)' does not enforce Enterprise/Education/IoT-only Recall deny-list or agent policies; the target planner leaves those values untouched and reports them NotApplicable")
    }
    if ($windows.Release -eq '24H2' -and [int]$windows.UpdateBuildRevision -lt 3915) {
        $warnings.Add("Windows 11 24H2 build $($windows.FullBuild) predates the documented Recall policy floor 26100.3915; update Windows before expecting Recall controls to be effective")
    }
    $applicabilityNotes.Add('AllowRecallExport is EEA-only and Insider-scoped; without authoritative device-geography attestation the target planner leaves it untouched and reports NotApplicable')
    $applicabilityNotes.Add('ShowCopilotButton is a legacy taskbar preference with no effect on the current Copilot app; the target planner leaves it untouched and reports NotApplicable')
    $warnings.Add('AgentConnectorAccessPolicy is not configured: Microsoft currently redirects its promised JSON-schema link back to the CSP page without publishing the schema; the separate connector policies are set to Force Disable')
    $warnings.Add('The deprecated TurnOffWindowsCopilot policy does not block the current Microsoft Copilot MSIX app; Microsoft documents AppLocker/App Control for launch prevention, which remains outside this exact-restore AntiAI profile. Exact package uninstall is available only through Privacy Tier 1/Tier 2 destructive opt-in')

    return [PSCustomObject]@{
        DocumentationAsOf       = '2026-07-12'
        SupportedWindowsProfile = [bool]$windows.IsSupported
        WindowsRelease          = [string]$windows.Release
        WindowsBuild            = [string]$windows.FullBuild
        WindowsBuildNumber      = [int]$windows.BuildNumber
        WindowsUBR              = [int]$windows.UpdateBuildRevision
        SupportLevel            = [string]$windows.SupportLevel
        Edition                 = [string]$windows.Edition
        EditionFamily           = $editionFamily
        OperatingSystemSKU      = $sku
        CommercialEdition       = $commercialEdition
        ProOrHigherEdition      = $proOrHigherEdition
        InsiderPreviewProfile   = [bool]$insiderEnrollment
        RecallBasePolicy        = if ($windows.Release -eq '24H2' -and [int]$windows.UpdateBuildRevision -lt 3915) { 'Below documented servicing floor' } else { 'Build-applicable' }
        RecallEnterprisePolicy  = if ($commercialEdition) { 'Edition-applicable' } else { 'Edition-inapplicable' }
        InsiderPreviewEvidence  = @($insiderEvidence)
        AgentPolicies           = if ($commercialEdition -and $insiderEnrollment) { 'Preview-applicable by OS/enrollment evidence' } elseif ($commercialEdition) { 'Insider-only/forward-looking' } else { 'Edition-inapplicable' }
        AgentAccessPolicy       = 'Not configured; Microsoft JSON schema link unresolved, connector off-switches used instead'
        RecallExportPolicy      = 'EEA-only; not written without authoritative device-geography attestation'
        CurrentCopilotApp       = 'Not covered; AppLocker/App Control required'
        Warnings                = @($warnings)
        ApplicabilityNotes      = @($applicabilityNotes)
    }
}
