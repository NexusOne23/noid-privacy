#Requires -Version 5.1

function Get-AntiAITargetPlan {
    <#
    .SYNOPSIS
        Classifies every declared AntiAI registry target as Applicable or NotApplicable.

    .DESCRIPTION
        Uses Microsoft-documented Windows build/edition/preview and product
        version constraints. Unknown applicability is conservative: the target
        is left untouched rather than written as forward-looking registry state.
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
    $recallFloor = ($build -gt 26100 -or ($build -eq 26100 -and $ubr -ge 3915))
    $paintFloor = ($build -gt 26100 -or ($build -eq 26100 -and $ubr -ge 3360))
    $settingsAgentFloor = ($build -gt 26100 -or ($build -eq 26100 -and $ubr -ge 4770))

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

    function Get-InstalledNotepadVersion {
        if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
            throw 'Get-AppxPackage is unavailable; Notepad policy applicability is unknown'
        }
        $packages = @(Get-AppxPackage -AllUsers -Name 'Microsoft.WindowsNotepad' -ErrorAction Stop)
        if ($packages.Count -eq 0) { return $null }
        $versions = @($packages | ForEach-Object {
                $parsed = [version]'0.0'
                if (-not [version]::TryParse([string]$_.Version, [ref]$parsed)) {
                    throw "Installed Notepad version is not parseable: '$($_.Version)'"
                }
                $parsed
            } | Sort-Object)
        return @($versions | Sort-Object -Descending)[0]
    }

    $edgeVersion = Get-InstalledEdgeVersion
    $notepadVersion = Get-InstalledNotepadVersion
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
            $isApplicable = $proOrHigher -and $recallFloor
            $reason = 'Requires Pro/Enterprise/Education/IoT and Windows build 26100.3915+'
        }
        elseif ($name -in $recallEnterpriseNames) {
            $isApplicable = $commercial -and $recallFloor
            $reason = 'Requires Enterprise/Education/IoT and Windows build 26100.3915+'
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
            $isApplicable = $commercial -and $settingsAgentFloor
            $reason = 'Requires Enterprise/Education/IoT and Windows build 26100.4770+; the Settings Agent itself is present only on eligible Copilot+ PCs'
        }
        elseif ($name -eq 'AllowRecallExport') {
            $isApplicable = $false
            $reason = 'EEA-only Insider policy; this framework has no authoritative device-geography attestation'
        }
        elseif ($name -eq 'DisableClickToDo') {
            $isApplicable = $proOrHigher -and $recallFloor
            $reason = 'Requires Pro/Enterprise/Education/IoT and Windows build 26100.3915+; Click to Do itself requires a Copilot+ PC or eligible Cloud PC'
        }
        elseif ($name -in $paintNames) {
            $isApplicable = $proOrHigher -and $paintFloor
            $reason = 'Requires Pro/Enterprise/Education/IoT and Windows build 26100.3360+'
        }
        elseif ($name -eq 'DisableAIFeatures') {
            $minimumNotepad = [version]'11.2503.16.0'
            $isApplicable = $null -ne $notepadVersion -and $notepadVersion -ge $minimumNotepad
            $reason = if ($null -eq $notepadVersion) { 'Microsoft Notepad package is not installed' } else { "Requires Windows 11 and Notepad $minimumNotepad+; installed $notepadVersion" }
        }
        elseif ($name -in @('TurnOffWindowsCopilot', 'SetCopilotHardwareKey', 'LetAppsAccessSystemAIModels')) {
            # Windows Administrative Template policies are documented for the
            # managed-policy editions, the same rule Privacy applies to Home.
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
        NotepadVersion       = if ($notepadVersion) { $notepadVersion.ToString() } else { $null }
    }
}
