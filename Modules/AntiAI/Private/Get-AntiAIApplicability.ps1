#Requires -Version 5.1

function Test-AntiAIMdmRegistration {
    <#
    .SYNOPSIS
        Query Windows' documented MDM registration API without collecting UPN.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not ('NoIDAntiAIMdmRegistrationInspector' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NoIDAntiAIMdmRegistrationInspector
{
    [DllImport("MDMRegistration.dll", CharSet = CharSet.Unicode)]
    private static extern int IsDeviceRegisteredWithManagement(
        [MarshalAs(UnmanagedType.Bool)] out bool isRegistered,
        uint upnBufferLength,
        IntPtr upnBuffer);

    public static bool IsRegistered()
    {
        bool registered;
        int hr = IsDeviceRegisteredWithManagement(out registered, 0, IntPtr.Zero);
        if (hr != 0) Marshal.ThrowExceptionForHR(hr);
        return registered;
    }
}
'@ -ErrorAction Stop
    }
    return [bool][NoIDAntiAIMdmRegistrationInspector]::IsRegistered()
}

function Get-AntiAIManagementState {
    <#
    .SYNOPSIS
        Reports whether Microsoft Edge Update treats this device as managed.

    .DESCRIPTION
        Edge Update loads its policies only on a device that is joined to an
        Active Directory domain or registered with an MDM service; on any other
        device it logs "Machine is not Enterprise Managed" and ignores every
        value under HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate. Domain state
        comes from Win32_ComputerSystem and MDM state from
        IsDeviceRegisteredWithManagement. A failed query leaves the state
        unknown, never managed.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $errors = [System.Collections.Generic.List[string]]::new()
    $domainJoined = $null
    try {
        $computers = @(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop)
        if ($computers.Count -ne 1 -or $null -eq $computers[0] -or
            -not $computers[0].PSObject.Properties['PartOfDomain'] -or
            $computers[0].PartOfDomain -isnot [bool]) {
            throw 'Win32_ComputerSystem returned incomplete or ambiguous domain-membership evidence'
        }
        $domainJoined = [bool]$computers[0].PartOfDomain
    }
    catch { $errors.Add("Domain-join query failed: $($_.Exception.Message)") }

    $mdmRegistered = $null
    try { $mdmRegistered = Test-AntiAIMdmRegistration }
    catch { $errors.Add("MDM-registration query failed: $($_.Exception.Message)") }

    # Either positive answer is enough; a negative answer needs both queries.
    $managed = if ($domainJoined -eq $true -or $mdmRegistered -eq $true) { $true }
        elseif ($errors.Count -eq 0) { $false }
        else { $null }
    return [PSCustomObject]@{
        DomainJoined  = $domainJoined
        MdmRegistered = $mdmRegistered
        Managed       = $managed
        QueryErrors   = @($errors)
    }
}

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
            $release = '26H2'; $supportLevel = 'Stable'
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
            IsSupported    = ($supportLevel -eq 'Stable')
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
    # The generated WindowsAI CSP applicability tables include IoT Enterprise
    # for the commercial-only policies. DisableRecallDataProviders also has a
    # stale/conflicting prose note saying Enterprise/Education only. Follow the
    # structured applicability metadata and keep IoT runtime enforcement in the
    # Windows release gate instead of silently pretending the conflict is gone.
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
    $selfHostSelectionPath = 'HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Selection'
    if (Test-NoIDRegistryKey -LiteralPath $selfHostSelectionPath) {
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
    $agentPolicyProfile = ($windows.Release -eq '26H2' -or $insiderEnrollment)
    if (-not $commercialEdition) {
        $applicabilityNotes.Add("Edition '$($windows.Edition)' does not enforce Enterprise/Education/IoT-only Recall deny-list or agent policies; the target planner leaves those values untouched and reports them NotApplicable")
    }
    if ($windows.Release -eq '24H2' -and [int]$windows.UpdateBuildRevision -lt 3915) {
        $warnings.Add("Windows 11 24H2 build $($windows.FullBuild) predates the documented Recall policy floor 26100.3915; update Windows before expecting Recall controls to be effective")
    }
    if ($proOrHigherEdition -and
        ([int]$windows.BuildNumber -gt 26100 -or
         ([int]$windows.BuildNumber -eq 26100 -and [int]$windows.UpdateBuildRevision -ge 3915))) {
        $applicabilityNotes.Add('Recall policies delete existing Recall snapshots. NoID Restore restores recorded registry policy values; it cannot recover deleted snapshots or automatically reinstall removed Recall components.')
    }
    $applicabilityNotes.Add('AllowRecallExport is EEA-only and Insider-scoped; without authoritative device-geography attestation the target planner leaves it untouched and reports NotApplicable')
    $applicabilityNotes.Add('AgentConnectorAccessPolicy is not configured: Microsoft currently redirects its promised JSON-schema link back to the CSP page without publishing the schema; ConfigureAgentConnectors is set to Force Disable instead')
    $management = Get-AntiAIManagementState
    if ($null -eq $management.Managed) {
        $warnings.Add("Device management could not be checked, so the Copilot install block for Microsoft Edge Update is not written: $($management.QueryErrors -join '; ')")
    }
    elseif (-not $management.Managed) {
        $applicabilityNotes.Add('This device is neither domain-joined nor MDM-enrolled. Microsoft Edge Update reads none of its policies on such a device, so the Copilot install block for Edge Update is left unwritten and reported NotApplicable; Microsoft offers no other control that stops Edge Update from installing the Copilot app here')
    }
    $applicabilityNotes.Add('The Microsoft Copilot app is restricted by its documented policies (no browsing, no Cowork actions; no installs through Microsoft Edge Update on managed devices) but is not uninstalled or blocked from launching; Microsoft documents AppLocker/App Control for launch prevention, which remains outside this exact-restore AntiAI profile. Exact package uninstall is available only through Privacy Tier 1/Tier 2 destructive opt-in')
    $applicabilityNotes.Add('Microsoft marks most Edge Copilot/AI policies as not applying to profiles signed in with a personal Microsoft account on managed devices, and several apply only to work (Entra ID) profiles; registry verification does not claim the browser enforces them in every profile')

    return [PSCustomObject]@{
        DocumentationAsOf       = '2026-10-08'
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
        AgentPolicyProfile      = [bool]$agentPolicyProfile
        ManagedDevice           = $management.Managed
        DomainJoined            = $management.DomainJoined
        MdmRegistered           = $management.MdmRegistered
        RecallBasePolicy        = if ($windows.Release -eq '24H2' -and [int]$windows.UpdateBuildRevision -lt 3915) { 'Below documented servicing floor' } else { 'Build-applicable' }
        RecallEnterprisePolicy  = if ($commercialEdition) { 'Edition-applicable' } else { 'Edition-inapplicable' }
        InsiderPreviewEvidence  = @($insiderEvidence)
        AgentPolicies           = if ($commercialEdition -and $agentPolicyProfile) { 'Current WindowsAI CSP profile for explicit 26H2 or detected Insider enrollment' } elseif ($commercialEdition) { 'Requires documented Insider enrollment on this release' } else { 'Edition-inapplicable' }
        AgentAccessPolicy       = 'Not configured; Microsoft JSON schema link unresolved, ConfigureAgentConnectors Force Disable used instead'
        RecallExportPolicy      = 'EEA-only; not written without authoritative device-geography attestation'
        CurrentCopilotApp       = 'App policies restrict browsing and Cowork actions; the Edge Update install block applies only on domain-joined or MDM-enrolled devices; launch blocking requires AppLocker/App Control'
        Warnings                = @($warnings)
        ApplicabilityNotes      = @($applicabilityNotes)
    }
}
