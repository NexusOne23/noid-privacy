#Requires -Version 5.1

function Assert-Windows11DecisionEvidence {
    <#
    .SYNOPSIS
        Compare a module's actual DryRun plan with its requested decisions.
        This validates decision routing, not the later effect of an Apply.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        [object[]]$AsrDefinitions = @()
    )

    $checked = [ordered]@{}
    $inactive = [System.Collections.Generic.List[string]]::new()
    function Read-DecisionField {
        param($Object, [string]$Name)
        if ($Object -is [System.Collections.IDictionary]) {
            if (-not $Object.Contains($Name)) { throw "Missing decision evidence: $Name" }
            return $Object[$Name]
        }
        if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name]) {
            throw "Missing decision evidence: $Name"
        }
        return $Object.$Name
    }
    function Assert-DecisionField {
        param($Object, [string]$Name, $Expected, [string]$Label = $Name)
        $actual = Read-DecisionField $Object $Name
        $valid = if ($Expected -is [bool]) {
            $actual -is [bool] -and $actual -eq $Expected
        }
        elseif ($Expected -is [string]) {
            $actual -is [string] -and $actual -ceq $Expected
        }
        else {
            ($actual -is [int] -or $actual -is [long]) -and $actual -eq $Expected
        }
        if (-not $valid) { throw "Decision evidence differs: $Label (expected $Expected, got $actual)" }
        $checked[$Label] = $actual
    }

    $decisions = $Scenario.Decisions
    switch ([string]$Scenario.Module) {
        'SecurityBaseline' {
            foreach ($name in @('BitLockerUSBEnforcement', 'SubmitAllSamples', 'SmartScreenWarnMode', 'StandardUserElevationMode', 'AdminProtectionMode')) {
                Assert-DecisionField $Result.Details $name $decisions[$name]
            }
            Assert-DecisionField $Result.Details 'ConsentPromptBehaviorUser' $(if ($decisions.standardUserElevationMode -ceq 'Strict') { 0 } else { 1 })
            Assert-DecisionField $Result.Details 'TypeOfAdminApprovalMode' $(if ($decisions.adminProtectionMode -ceq 'Classic') { 1 } else { 2 })
        }
        'ASR' {
            $cloudEnabled = Read-DecisionField $Environment 'CloudProtectionEnabled'
            $configMgr = Read-DecisionField $Environment 'ConfigMgrDetected'
            if ($cloudEnabled -isnot [bool] -or $configMgr -isnot [bool]) { throw 'ASR environment evidence is not Boolean' }
            Assert-DecisionField $Result 'CloudProtectionEnabled' $cloudEnabled
            Assert-DecisionField $Result 'ConfigMgrDetected' $configMgr
            if (-not $cloudEnabled -and -not $decisions.continueWithoutCloud) {
                Assert-DecisionField $Result 'Success' $false
                Assert-DecisionField $Result 'Status' 'Failed'
                Assert-DecisionField $Result 'RulesPreviewed' 0
                Assert-DecisionField $Result 'BackupCreated' $false
                if (@($Result.Details.RequestedActions).Count -ne 0 -or
                    @($Result.Errors | Where-Object { [string]$_ -match 'cloud protection required, continueWithoutCloud=false' }).Count -ne 1) {
                    throw 'ASR cloud refusal did not stop at the expected pre-backup boundary'
                }
                break
            }
            Assert-DecisionField $Result 'Status' 'DryRun'
            $expectedActions = @{}
            foreach ($rule in $AsrDefinitions) {
                if ($rule.PSObject.Properties['WindowsClientApplicable'] -and -not $rule.WindowsClientApplicable) { continue }
                $id = ([guid]([string]$rule.GUID)).ToString('D').ToLowerInvariant()
                if ($expectedActions.ContainsKey($id)) { throw 'ASR oracle has duplicate identities' }
                $expectedActions[$id] = [int]$rule.Action
            }
            if ($expectedActions.Count -ne 18) { throw 'ASR oracle does not cover all 18 Windows-client rules' }
            $expectedActions['d1e49aac-8f56-4280-b9ba-993a6d77406c'] = if ($decisions.usesManagementTools -or $configMgr) { 2 } else { 1 }
            $expectedActions['01443614-cd74-433a-b99e-2ecdc07bfc25'] = if ($decisions.allowNewSoftware) { 2 } else { 1 }
            $actions = @($Result.Details.RequestedActions)
            if ($actions.Count -ne $expectedActions.Count) { throw 'ASR requested-action count differs' }
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($action in $actions) {
                $id = ([guid]([string]$action.Guid)).ToString('D').ToLowerInvariant()
                if (-not $seen.Add($id) -or -not $expectedActions.ContainsKey($id)) { throw 'ASR requested plan has an unknown or duplicate identity' }
                Assert-DecisionField $action 'Action' $expectedActions[$id] ('ASR/' + $id)
            }
            Assert-DecisionField $Result 'RulesPreviewed' 18
            Assert-DecisionField $Result 'RulesNotApplicable' 1
            if ($cloudEnabled) { $inactive.Add('continueWithoutCloud') }
            if ($configMgr) { $inactive.Add('usesManagementTools') }
        }
        'DNS' {
            Assert-DecisionField $Result 'Provider' ([string]$decisions.provider)
            $keep = $decisions.provider -ceq 'KEEP'
            Assert-DecisionField $Result 'DoHMode' $(if ($keep) { 'KEEP' } else { [string]$decisions.dohMode })
            Assert-DecisionField $Result 'Status' $(if ($keep) { 'Success' } else { 'DryRun' })
            if ($keep) { $inactive.Add('dohMode') }
        }
        'Privacy' {
            Assert-DecisionField $Result 'Status' 'DryRun'
            Assert-DecisionField $Result 'Mode' ([string]$decisions.mode)
            $preview = Read-DecisionField $Result 'PreviewDecisions'
            $clipboardSelected = $decisions.mode -cne 'MSRecommended' -or [bool]$decisions.disableCloudClipboard
            Assert-DecisionField $preview 'CloudClipboardTargetCount' $(if ($clipboardSelected) { 1 } else { 0 })
            if ($clipboardSelected) {
                Assert-DecisionField $preview 'CloudClipboardTargetType' 'DWord'
                Assert-DecisionField $preview 'CloudClipboardTargetValue' 0
            }
            Assert-DecisionField $preview 'Tier1PolicyRemovalSelected' ([bool]$decisions.applyStorePackagePolicy)
            Assert-DecisionField $preview 'Tier2BloatwareRemovalSelected' ($decisions.removeBloatwareApps -ceq 'standard')
            Assert-DecisionField $preview 'WeatherWidgetRemovalSelected' ([bool]$decisions.removeWeatherWidget)
            if ($decisions.mode -cne 'MSRecommended') { $inactive.Add('disableCloudClipboard') }
        }
        'AntiAI' {
            if (@($decisions.Keys).Count -ne 0) { throw 'AntiAI matrix unexpectedly contains choices' }
            Assert-DecisionField $Result 'DeclaredPolicyTargets' 50
            Assert-DecisionField $Result 'TotalFeatures' 12
            $canonical = @{}
            foreach ($target in @(Read-DecisionField $Environment 'AntiAITargets')) {
                $id = ([string]$target.Path + '::' + [string]$target.Name).ToLowerInvariant()
                if ($canonical.ContainsKey($id) -or [string]::IsNullOrWhiteSpace([string]$target.Feature)) {
                    throw 'AntiAI oracle contains an ambiguous target or missing feature'
                }
                $canonical[$id] = [string]$target.Feature
            }
            if ($canonical.Count -ne 50) { throw 'AntiAI oracle does not cover all 50 registry identities' }
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $features = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($category in @('ApplicableTargetPlan', 'NotApplicableTargetPlan')) {
                $targets = @(Read-DecisionField $Result $category)
                foreach ($target in $targets) {
                    $id = ([string]$target.Path + '::' + [string]$target.Name).ToLowerInvariant()
                    if (-not $seen.Add($id) -or -not $canonical.ContainsKey($id)) { throw 'AntiAI preview contains a duplicate or foreign target' }
                    if ($category -ceq 'ApplicableTargetPlan') { $null = $features.Add($canonical[$id]) }
                }
                $countField = if ($category -ceq 'ApplicableTargetPlan') { 'PreviewedPolicyTargets' } else { 'NotApplicablePolicyTargets' }
                Assert-DecisionField $Result $countField $targets.Count
            }
            if ($seen.Count -ne $canonical.Count) { throw 'AntiAI preview omits canonical target identities' }
            # Previewed counts applicable registry feature groups plus the URI
            # operation; TotalFeatures describes all twelve declared groups.
            Assert-DecisionField $Result 'Previewed' ($features.Count + 1)
        }
        'EdgeHardening' {
            Assert-DecisionField $Result 'Status' 'DryRun'
            Assert-DecisionField $Result 'AllowExtensions' ([bool]$decisions.allowExtensions)
            Assert-DecisionField $Result 'PoliciesSelected' $(if ($decisions.allowExtensions) { 30 } else { 31 })
            Assert-DecisionField $Result 'BaselineSelected' $(if ($decisions.allowExtensions) { 23 } else { 24 })
            Assert-DecisionField $Result 'PrivacySelected' 7
            if ([int]$Result.PoliciesPreviewed + [int]$Result.PoliciesNotApplicable -ne [int]$Result.PoliciesSelected) {
                throw 'Edge preview does not cover the selected extension profile'
            }
        }
        'AdvancedSecurity' {
            foreach ($name in @('RdpHostSupported', 'WirelessDisplaySupported', 'DomainJoined')) {
                if ((Read-DecisionField $Environment $name) -isnot [bool]) { throw "AdvancedSecurity environment evidence is not Boolean: $name" }
            }
            $securityProfile = [string]$decisions.securityProfile
            $balanced = $securityProfile -ceq 'Balanced'
            $maximum = $securityProfile -ceq 'Maximum'
            $rdp = $Environment.RdpHostSupported -and ($maximum -or ($balanced -and $decisions.disableRDP))
            $shares = -not $Environment.DomainJoined -or $maximum -or ($balanced -and $decisions.forceAdminShares)
            Assert-DecisionField $Result 'Status' 'DryRun'
            Assert-DecisionField $Result 'SecurityProfile' $securityProfile
            Assert-DecisionField $Result 'SkipFirewallLayer' ([bool]$decisions.skipFirewallLayer)
            Assert-DecisionField $Result 'DisableRDP' ([bool]$rdp)
            Assert-DecisionField $Result 'AdminSharesDisabled' ([bool]$shares)
            Assert-DecisionField $Result 'DisableUPnP' ((-not $balanced) -or [bool]$decisions.disableUPnP)
            Assert-DecisionField $Result 'DisableWirelessDisplayCompletely' ($Environment.WirelessDisplaySupported -and [bool]$decisions.disableWirelessDisplay)
            Assert-DecisionField $Result 'DisableDiscoveryProtocolsCompletely' ($maximum -and [bool]$decisions.disableDiscoveryProtocols)
            Assert-DecisionField $Result 'DisableIPv6Completely' ($maximum -and [bool]$decisions.disableIPv6)
            Assert-DecisionField $Result 'EnableFirewallShieldsUp' ($maximum -and -not $decisions.skipFirewallLayer)
            Assert-DecisionField $Result 'FirewallLayer' $(if ($decisions.skipFirewallLayer) { 'Skipped' } else { 'WouldApply' })
            if (-not $balanced -or -not $Environment.RdpHostSupported) { $inactive.Add('disableRDP') }
            if (-not $balanced) { $inactive.Add('disableUPnP') }
            if (-not $balanced -or -not $Environment.DomainJoined) { $inactive.Add('forceAdminShares') }
            if (-not $Environment.WirelessDisplaySupported) { $inactive.Add('disableWirelessDisplay') }
            if (-not $maximum) { $inactive.Add('disableDiscoveryProtocols'); $inactive.Add('disableIPv6') }
        }
        default { throw "No decision evidence oracle for $($Scenario.Module)" }
    }
    return [PSCustomObject]@{ Verified = $true; CheckedValues = [PSCustomObject]$checked; InactiveChoices = @($inactive) }
}
