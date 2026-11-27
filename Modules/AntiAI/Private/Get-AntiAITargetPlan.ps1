#Requires -Version 5.1

function Get-AntiAITargetPlan {
    <#
    .SYNOPSIS
        Classifies every declared AntiAI registry target as Applicable or NotApplicable.

    .DESCRIPTION
        Uses Microsoft-documented Windows edition, preview and management
        constraints. Policies of features that a Windows update or a Store app
        update adds later (Recall, Click to Do, Paint, the Settings agent,
        Notepad, Edge, the Copilot app) are staged on every eligible edition, so
        the protection is in place when the feature arrives and Verify does not
        turn red after such an update. Unknown edition or preview applicability
        stays conservative: the target is left untouched.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$Targets,

        [Parameter(Mandatory = $false)]
        $Applicability
    )

    $declaredTargets = if ($PSBoundParameters.ContainsKey('Targets')) { @($Targets) } else { @(Get-AntiAIRegistryTargets) }
    $applicabilityState = if ($PSBoundParameters.ContainsKey('Applicability')) { $Applicability } else { Get-AntiAIApplicability }
    if ($declaredTargets.Count -ne 50) { throw "AntiAI target plan requires 50 declared targets; got $($declaredTargets.Count)" }
    foreach ($property in @(
            'SupportedWindowsProfile', 'WindowsBuildNumber', 'WindowsUBR', 'CommercialEdition',
            'ProOrHigherEdition', 'InsiderPreviewProfile', 'AgentPolicyProfile', 'ManagedDevice'
        )) {
        if (-not $applicabilityState.PSObject.Properties[$property]) {
            throw "AntiAI applicability is missing '$property'"
        }
    }
    if (-not [bool]$applicabilityState.SupportedWindowsProfile) {
        throw 'AntiAI target applicability cannot be planned on an unsupported Windows profile'
    }

    $build = [int]$applicabilityState.WindowsBuildNumber
    $ubr = [int]$applicabilityState.WindowsUBR
    $proOrHigher = [bool]$applicabilityState.ProOrHigherEdition
    $commercial = [bool]$applicabilityState.CommercialEdition
    $agentPolicyProfile = [bool]$applicabilityState.AgentPolicyProfile
    $insiderProfile = [bool]$applicabilityState.InsiderPreviewProfile
    # $null means the management queries failed; only a proven $true counts.
    $managedDevice = $applicabilityState.ManagedDevice -eq $true
    $managementKnown = $null -ne $applicabilityState.ManagedDevice
    # Documented minimum builds. Below them the policy is staged, not skipped;
    # only the Insider-only Recall data-provider policy keeps its floor.
    $recallFloor = ($build -gt 26100 -or ($build -eq 26100 -and $ubr -ge 3915))

    function Get-InstalledEdgeVersion {
        $versionTexts = [System.Collections.Generic.List[string]]::new()
        $machineCandidates = [System.Collections.Generic.List[string]]::new()
        $machineAppPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe'
        if (Test-NoIDRegistryKey -LiteralPath $machineAppPath) {
            $machineAppKey = Get-Item -LiteralPath $machineAppPath -ErrorAction Stop
            $registeredPath = [string]$machineAppKey.GetValue(
                '', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            if (-not [string]::IsNullOrWhiteSpace($registeredPath)) {
                $machineCandidates.Add([Environment]::ExpandEnvironmentVariables($registeredPath))
            }
        }
        foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$root)) {
                $machineCandidates.Add((Join-Path $root 'Microsoft\Edge\Application\msedge.exe'))
            }
        }
        foreach ($candidate in @($machineCandidates)) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction Stop) {
                $versionTexts.Add([string](Get-Item -LiteralPath $candidate -ErrorAction Stop).VersionInfo.FileVersion)
            }
        }

        # Enumerate every real user profile instead of requiring a running
        # Explorer. Machine policy covers logged-out per-user installations too.
        $profileListRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        if (Test-NoIDRegistryKey -LiteralPath $profileListRoot) {
            foreach ($profileKey in @(Get-ChildItem -LiteralPath $profileListRoot -ErrorAction Stop)) {
                $profileSid = [string]$profileKey.PSChildName
                if ($profileSid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$') { continue }
                $userCandidates = [System.Collections.Generic.List[string]]::new()
                $profilePathRaw = [string]$profileKey.GetValue(
                    'ProfileImagePath', $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                if (-not [string]::IsNullOrWhiteSpace($profilePathRaw)) {
                    $profilePath = [Environment]::ExpandEnvironmentVariables($profilePathRaw)
                    $userCandidates.Add((Join-Path $profilePath 'AppData\Local\Microsoft\Edge\Application\msedge.exe'))
                }
                $userAppPath = "Registry::HKEY_USERS\$profileSid\Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"
                if (Test-NoIDRegistryKey -LiteralPath $userAppPath) {
                    $userAppKey = Get-Item -LiteralPath $userAppPath -ErrorAction Stop
                    $userRegisteredPath = [string]$userAppKey.GetValue(
                        '', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                    if (-not [string]::IsNullOrWhiteSpace($userRegisteredPath)) {
                        $userCandidates.Add([Environment]::ExpandEnvironmentVariables($userRegisteredPath))
                    }
                }
                foreach ($candidate in @($userCandidates | Select-Object -Unique)) {
                    if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction Stop) {
                        $versionTexts.Add([string](Get-Item -LiteralPath $candidate -ErrorAction Stop).VersionInfo.FileVersion)
                    }
                }
            }
        }
        $versions = [System.Collections.Generic.List[System.Version]]::new()
        foreach ($versionText in @($versionTexts | Sort-Object -Unique)) {
            $parsed = [version]'0.0'
            if (-not [version]::TryParse(
                    ($versionText -replace '[^0-9.].*$', ''),
                    [ref]$parsed
                )) { continue }
            $versions.Add($parsed)
        }
        if ($versions.Count -eq 0) { return $null }
        return @($versions | Sort-Object -Descending)[0]
    }

    $edgeVersion = Get-InstalledEdgeVersion
    $edgePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    $edgeMinimumMajor = @{
        HubsSidebarEnabled = 99; StandaloneHubsSidebarEnabled = 114
        Microsoft365CopilotChatIconEnabled = 139; CopilotAddressBarSuggestionsEnabled = 149
        NewTabPageBingChatEnabled = 117
        CopilotNewTabPageEnabled = 148; AllowBrowsingWithCopilot = 148
        M365LinksAutoOpenCopilotEnabled = 148; CopilotPageContext = 124
        EdgeEntraCopilotPageContext = 130; ShareBrowsingHistoryWithCopilotSearchAllowed = 143
        GenAILocalFoundationalModelSettings = 132; BuiltInAIAPIsEnabled = 138
        ComposeInlineEnabled = 115; EdgeHistoryAISearchEnabled = 138
        AIGenThemesEnabled = 122; VisualSearchEnabled = 95
        TextPredictionEnabled = 104; TabServicesEnabled = 113; EdgeAutofillMlEnabled = 132
        MicrosoftEditorProofingEnabled = 105; CopilotCoworkToolActionsEnabled = 152
        ProactiveAuthWorkflowEnabled = 126
    }
    # Machine policies for products Windows can install later (the Copilot app,
    # Microsoft Execution Containers). Like the Edge policies they are staged
    # whether or not the product is present today.
    $stagedProductPolicies = @{
        'HKLM:\SOFTWARE\Policies\Microsoft\Copilot' = 'Microsoft Copilot app 152+ machine policy; staged whether or not the app is installed'
        'HKLM:\SOFTWARE\Policies\Mxc' = 'Microsoft Execution Containers machine policy; staged whether or not an agent uses MXC'
    }
    $edgeUpdatePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
    # Per-user startup tasks of packaged Copilot apps. The key exists only once
    # the package is registered for the user; a missing key is never created.
    $startupTaskApps = @{
        'Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\WebViewHostStartupId' = 'Microsoft 365 Copilot app'
        'Microsoft.Copilot_8wekyb3d8bbwe\Copilot.StartupTaskId' = 'Copilot app'
    }
    $startupTaskPrefix = '\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\'
    $recallEnterpriseNames = @(
        'SetDenyAppListForRecall', 'DenyAppListForRecall', 'SetDenyUriListForRecall',
        'DenyUriListForRecall', 'SetMaximumStorageDurationForRecallSnapshots',
        'SetMaximumStorageSpaceForRecallSnapshots'
    )
    $agentNames = @('ConfigureAgentConnectors', 'AgentConsentDuration')
    $paintNames = @('DisableCocreator', 'DisableGenerativeFill', 'DisableImageCreator')

    $applicableTargets = [System.Collections.Generic.List[object]]::new()
    $notApplicableTargets = [System.Collections.Generic.List[object]]::new()
    foreach ($target in $declaredTargets) {
        $name = [string]$target.Name
        $targetPath = [string]$target.Path
        $isApplicable = $false
        $reason = $null
        if ($targetPath -eq $edgePolicyPath) {
            if (-not $edgeMinimumMajor.ContainsKey($name)) {
                throw "AntiAI Edge target has no documented minimum version: $name"
            }
            $minimum = [int]$edgeMinimumMajor[$name]
            # Match EdgeHardening exactly: documented machine policies are safe
            # to stage for absent and older Edge versions. The version remains
            # evidence about current runtime consumption, never an excuse to
            # silently shrink future AI/Copilot coverage.
            $isApplicable = $true
            $reason = if ($null -eq $edgeVersion) {
                "Microsoft Edge is absent; documented Edge $minimum+ policy is staged for a future installation"
            }
            elseif ($edgeVersion.Major -lt $minimum) {
                "Installed Edge $edgeVersion is below $minimum; policy is staged for a future update"
            }
            else { "Installed Edge $edgeVersion can consume the Edge $minimum+ policy" }
        }
        elseif ($stagedProductPolicies.ContainsKey($targetPath)) {
            $isApplicable = $true
            $reason = [string]$stagedProductPolicies[$targetPath]
        }
        elseif ($targetPath -eq $edgeUpdatePolicyPath) {
            # Edge Update loads its policies only on domain-joined or
            # MDM-registered devices ("Machine is not Enterprise Managed").
            $isApplicable = $managedDevice
            $reason = if (-not $managementKnown) {
                'Device management could not be checked; Microsoft Edge Update reads this policy only on domain-joined or MDM-enrolled devices'
            }
            else { 'Microsoft Edge Update reads its policies only on domain-joined or MDM-enrolled devices; this device is neither' }
        }
        elseif ($name -eq 'State' -and @($startupTaskApps.Keys | Where-Object {
                    $targetPath.EndsWith($startupTaskPrefix + $_, [StringComparison]::OrdinalIgnoreCase)
                }).Count -eq 1) {
            $appKey = @($startupTaskApps.Keys | Where-Object {
                    $targetPath.EndsWith($startupTaskPrefix + $_, [StringComparison]::OrdinalIgnoreCase)
                })[0]
            $isApplicable = Test-NoIDRegistryKey -LiteralPath $targetPath
            $reason = "The $($startupTaskApps[$appKey]) has no startup task registered for this user"
        }
        elseif ($name -in @('AllowRecallEnablement', 'DisableAIDataAnalysis')) {
            # Documented for 26100.3915+; staged on older 24H2 builds for that update.
            $isApplicable = $proOrHigher
            $reason = 'Requires Pro/Enterprise/Education/IoT'
        }
        elseif ($name -in $recallEnterpriseNames) {
            $isApplicable = $commercial
            $reason = 'Requires Enterprise/Education/IoT'
        }
        elseif ($name -eq 'DisableRecallDataProviders') {
            # The WindowsAI CSP documents this user policy for Windows Insider
            # builds only, and no official ADMX ships it. A supported release
            # alone is therefore not an applicable profile.
            $isApplicable = $commercial -and $insiderProfile -and $recallFloor
            $reason = 'Requires Enterprise/Education/IoT on a detected Windows Insider Preview build (26100.3915+); Microsoft documents no other applicability'
        }
        elseif ($name -in $agentNames) {
            $isApplicable = $commercial -and $agentPolicyProfile
            $reason = 'Requires Enterprise/Education/IoT and the explicit 26H2 or detected Insider WindowsAI policy profile'
        }
        elseif ($name -eq 'DisableSettingsAgent') {
            # Documented for 26100.4770+; staged on older 24H2 builds and on PCs
            # that are not Copilot+ PCs, where the agent itself is absent.
            $isApplicable = $commercial
            $reason = 'Requires Enterprise/Education/IoT'
        }
        elseif ($name -eq 'AllowRecallExport') {
            $isApplicable = $false
            $reason = 'EEA-only Insider policy; this framework has no authoritative device-geography attestation'
        }
        elseif ($name -eq 'DisableClickToDo') {
            # Documented for 26100.3915+ on Copilot+ PCs and eligible Cloud PCs;
            # staged elsewhere for that update or hardware.
            $isApplicable = $proOrHigher
            $reason = 'Requires Pro/Enterprise/Education/IoT'
        }
        elseif ($name -in $paintNames) {
            # Documented for 26100.3360+; staged on older 24H2 builds.
            $isApplicable = $proOrHigher
            $reason = 'Requires Pro/Enterprise/Education/IoT'
        }
        elseif ($name -eq 'DisableAIFeatures') {
            # Notepad reads its documented policy from 11.2503.16 on. Like the Edge
            # policies it is staged for an absent or older Notepad: the Store
            # updates Notepad on its own, often while the hardening runs.
            $isApplicable = $true
            $reason = $null
        }
        elseif ($name -eq 'LetAppsAccessSystemAIModels') {
            # Measured on Windows 11 Home 26H2: Settings > Privacy > Text and image
            # generation is locked off by this policy, as on Pro (Privacy applies
            # the same AppPrivacy rule to Home).
            $isApplicable = $true
            $reason = $null
        }
        elseif ($name -in @('TurnOffWindowsCopilot', 'SetCopilotHardwareKey')) {
            # Windows Administrative Template policies are documented for the
            # managed-policy editions; Home honouring them is not measured.
            $isApplicable = $proOrHigher
            $reason = 'Microsoft policy applicability requires Pro/Enterprise/Education/IoT'
        }
        else {
            throw "AntiAI target has no applicability classification: $($target.Path)::$name"
        }

        if ($isApplicable) {
            $applicableTargets.Add($target)
        }
        else {
            $notApplicableTargets.Add([PSCustomObject]@{
                    Path = [string]$target.Path
                    Name = $name
                    Feature = [string]$target.Feature
                    Reason = $reason
                })
        }
    }
    if ($applicableTargets.Count + $notApplicableTargets.Count -ne 50) {
        throw 'AntiAI target plan does not reconcile to the declared 50 targets'
    }
    return [PSCustomObject]@{
        DeclaredCount        = 50
        ApplicableCount      = $applicableTargets.Count
        NotApplicableCount   = $notApplicableTargets.Count
        ApplicableTargets    = @($applicableTargets)
        NotApplicableTargets = @($notApplicableTargets)
        EdgeVersion          = if ($edgeVersion) { $edgeVersion.ToString() } else { $null }
    }
}
