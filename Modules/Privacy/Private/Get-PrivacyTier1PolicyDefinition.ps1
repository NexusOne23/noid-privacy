#Requires -Version 5.1

function Get-PrivacyTier1PolicyDefinition {
    <#
    .SYNOPSIS
        Loads and validates the exact native Tier 1 app-removal policy inventory.

    .DESCRIPTION
        The independent expected app/PFN/value map prevents a count-only or
        broad subtree allowlist from turning a typo, CSP presentation ID, or
        config drift into a new owned registry target. The byte-level contract
        is pinned to the current inbox ADMX plus an actual gpedit/gpupdate diff.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $definitionFile = [string]$MyInvocation.MyCommand.ScriptBlock.File
    if ([string]::IsNullOrWhiteSpace($definitionFile)) { throw 'Privacy Tier 1 helper source path is unavailable' }
    $moduleRoot = Split-Path -Parent (Split-Path -Parent $definitionFile)
    $policyPath = Join-Path $moduleRoot 'Config\BloatwareRemovalPolicy.json'
    if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
        throw "Privacy BloatwareRemovalPolicy configuration is missing: $policyPath"
    }
    $policy = Get-Content -LiteralPath $policyPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$policy.MinBuildNumber -ne 26100 -or
        (@($policy.RequiredEditions | ForEach-Object { [string]$_ } | Sort-Object) -join ',') -cne 'Education,Enterprise' -or
        -not $policy.PSObject.Properties['PolicyTargets']) {
        throw 'Privacy Tier 1 policy metadata differs from the supported Enterprise/Education build-26100 contract'
    }

    $root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages'
    $expectedApps = [ordered]@{
        WindowsFeedbackHub = [PSCustomObject]@{ Pfn='Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe'; Value=0 }
        MicrosoftOfficeHub = [PSCustomObject]@{ Pfn='Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe'; Value=0 }
        Clipchamp = [PSCustomObject]@{ Pfn='Clipchamp.Clipchamp_yxz26nhyzhsrt'; Value=0 }
        Copilot = [PSCustomObject]@{ Pfn='Microsoft.Copilot_8wekyb3d8bbwe'; Value=1 }
        BingNews = [PSCustomObject]@{ Pfn='Microsoft.BingNews_8wekyb3d8bbwe'; Value=1 }
        Photos = [PSCustomObject]@{ Pfn='Microsoft.Windows.Photos_8wekyb3d8bbwe'; Value=0 }
        MicrosoftSolitaireCollection = [PSCustomObject]@{ Pfn='Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe'; Value=1 }
        MicrosoftStickyNotes = [PSCustomObject]@{ Pfn='Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe'; Value=0 }
        MSTeams = [PSCustomObject]@{ Pfn='MSTeams_8wekyb3d8bbwe'; Value=0 }
        Todo = [PSCustomObject]@{ Pfn='Microsoft.Todos_8wekyb3d8bbwe'; Value=0 }
        BingWeather = [PSCustomObject]@{ Pfn='Microsoft.BingWeather_8wekyb3d8bbwe'; Value=1 }
        OutlookForWindows = [PSCustomObject]@{ Pfn='Microsoft.OutlookForWindows_8wekyb3d8bbwe'; Value=0 }
        Paint = [PSCustomObject]@{ Pfn='Microsoft.Paint_8wekyb3d8bbwe'; Value=0 }
        QuickAssist = [PSCustomObject]@{ Pfn='MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe'; Value=0 }
        ScreenSketch = [PSCustomObject]@{ Pfn='Microsoft.ScreenSketch_8wekyb3d8bbwe'; Value=0 }
        WindowsCalculator = [PSCustomObject]@{ Pfn='Microsoft.WindowsCalculator_8wekyb3d8bbwe'; Value=0 }
        WindowsCamera = [PSCustomObject]@{ Pfn='Microsoft.WindowsCamera_8wekyb3d8bbwe'; Value=0 }
        MediaPlayer = [PSCustomObject]@{ Pfn='Microsoft.ZuneMusic_8wekyb3d8bbwe'; Value=0 }
        WindowsNotepad = [PSCustomObject]@{ Pfn='Microsoft.WindowsNotepad_8wekyb3d8bbwe'; Value=0 }
        WindowsSoundRecorder = [PSCustomObject]@{ Pfn='Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe'; Value=0 }
        WindowsTerminal = [PSCustomObject]@{ Pfn='Microsoft.WindowsTerminal_8wekyb3d8bbwe'; Value=0 }
        GamingApp = [PSCustomObject]@{ Pfn='Microsoft.GamingApp_8wekyb3d8bbwe'; Value=1 }
        XboxIdentityProvider = [PSCustomObject]@{ Pfn='Microsoft.XboxIdentityProvider_8wekyb3d8bbwe'; Value=1 }
        XboxSpeechToTextOverlay = [PSCustomObject]@{ Pfn='Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe'; Value=1 }
        XboxTCUI = [PSCustomObject]@{ Pfn='Microsoft.Xbox.TCUI_8wekyb3d8bbwe'; Value=1 }
    }
    $expectedPaths = @($root) + @($expectedApps.Values | ForEach-Object { "$root\$($_.Pfn)" })
    $actualPaths = @($policy.PolicyTargets.PSObject.Properties.Name)
    if ($actualPaths.Count -ne 26 -or
        @($actualPaths | Where-Object { $_ -notin $expectedPaths }).Count -gt 0 -or
        @($expectedPaths | Where-Object { $_ -notin $actualPaths }).Count -gt 0) {
        throw 'Privacy Tier 1 policy must contain exactly the native root and 25 gpedit PFN paths'
    }

    $targets = [System.Collections.Generic.List[object]]::new()
    $rootDefinition = $policy.PolicyTargets.$root
    if (@($rootDefinition.PSObject.Properties).Count -ne 2 -or
        -not $rootDefinition.PSObject.Properties['Enabled'] -or
        [string]$rootDefinition.Enabled.Type -cne 'DWord' -or
        [int]$rootDefinition.Enabled.Value -ne 1 -or
        -not $rootDefinition.PSObject.Properties['DynamicRemovalList'] -or
        [string]$rootDefinition.DynamicRemovalList.Type -cne 'MultiString' -or
        @($rootDefinition.DynamicRemovalList.Value).Count -ne 0) {
        throw 'Privacy Tier 1 root must contain only Enabled=DWord/1 and an empty DynamicRemovalList=MultiString'
    }
    $targets.Add([PSCustomObject]@{ Path=$root; Name='Enabled'; Type='DWord'; Value=1; Description='Enable native policy' })
    $targets.Add([PSCustomObject]@{
            Path=$root; Name='DynamicRemovalList'; Type='MultiString'; Value=[string[]]@()
            Description=[string]$rootDefinition.DynamicRemovalList.Description
        })

    foreach ($appId in $expectedApps.Keys) {
        $expected = $expectedApps[$appId]
        $pfn = [string]$expected.Pfn
        $path = "$root\$pfn"
        $definition = $policy.PolicyTargets.$path
        if (@($definition.PSObject.Properties).Count -ne 1 -or
            -not $definition.PSObject.Properties['RemovePackage'] -or
            [string]$definition.RemovePackage.Type -cne 'DWord' -or
            [int]$definition.RemovePackage.Value -ne [int]$expected.Value) {
            throw "Privacy Tier 1 app contract mismatch: $appId"
        }
        $targets.Add([PSCustomObject]@{
                Path=$path; Name='RemovePackage'; Type='DWord'; Value=[int]$expected.Value
                PolicyId=[string]$appId; PackageFamilyName=$pfn
                Description=[string]$definition.RemovePackage.Description
            })
    }

    return [PSCustomObject]@{
        Root = $root
        MinBuildNumber = 26100
        RequiredEditions = @('Enterprise','Education')
        Targets = @($targets)
        RemovalTargets = @($targets | Where-Object { $_.Name -eq 'RemovePackage' -and [int]$_.Value -eq 1 })
    }
}

function Get-PrivacyTier1PreCopilotPolicyDefinition {
    <#
    .SYNOPSIS
        Returns the immediately preceding PFN policy contract for restore only.

    .DESCRIPTION
        This closed contract differs from the current PFN inventory only in
        Copilot RemovePackage=0. New Backup/Apply never consumes it; it keeps
        already sealed pre-Copilot app inventories verifiable and recoverable.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $current = Get-PrivacyTier1PolicyDefinition
    $targets = [Collections.Generic.List[object]]::new()
    foreach ($target in @($current.Targets)) {
        $copy = [PSCustomObject][ordered]@{
            Path=[string]$target.Path; Name=[string]$target.Name
            Type=[string]$target.Type; Value=$target.Value
            Description=[string]$target.Description
        }
        foreach ($propertyName in @('PolicyId','PackageFamilyName')) {
            if ($target.PSObject.Properties[$propertyName]) {
                $copy | Add-Member -NotePropertyName $propertyName -NotePropertyValue ([string]$target.$propertyName)
            }
        }
        if ($copy.PSObject.Properties['PolicyId'] -and [string]$copy.PolicyId -eq 'Copilot') {
            $copy.Value = 0
        }
        $targets.Add($copy)
    }
    return [PSCustomObject]@{
        Root=[string]$current.Root
        MinBuildNumber=[int]$current.MinBuildNumber
        RequiredEditions=@($current.RequiredEditions)
        Targets=@($targets)
        RemovalTargets=@($targets | Where-Object {
                $_.Name -eq 'RemovePackage' -and [int]$_.Value -eq 1
            })
    }
}

function Get-PrivacyTier1LegacyV225PolicyDefinition {
    <#
    .SYNOPSIS
        Returns the closed, frozen v2.2.5 Tier 1 target set for exact restore only.

    .DESCRIPTION
        Legacy v2.2.5 incorrectly used CSP presentation IDs as registry subkeys. New
        Apply and Verify paths never consume this definition. Restore accepts
        the complete legacy set so an already sealed backup can reproduce its
        exact prestate; current/legacy mixtures remain invalid.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages'
    $legacyApps = [ordered]@{
        WindowsFeedbackHub = 0; MicrosoftOfficeHub = 0; Clipchamp = 0; Copilot = 0
        BingNews = 1; Photos = 0; MicrosoftSolitaireCollection = 1; MicrosoftStickyNotes = 1
        MSTeams = 0; Todo = 0; BingWeather = 1; OutlookForWindows = 0; Paint = 0
        QuickAssist = 0; ScreenSketch = 0; WindowsCalculator = 0; WindowsCamera = 0
        MediaPlayer = 0; WindowsNotepad = 0; WindowsSoundRecorder = 0; WindowsTerminal = 0
        GamingApp = 1; XboxGamingOverlay = 1; XboxIdentityProvider = 1
        XboxSpeechToTextOverlay = 1; XboxTCUI = 1
    }
    $targets = [Collections.Generic.List[object]]::new()
    $targets.Add([PSCustomObject]@{
            Path=$root; Name='Enabled'; Type='DWord'; Value=1
            Description='Legacy v2.2.5 policy root'
        })
    foreach ($appId in $legacyApps.Keys) {
        $targets.Add([PSCustomObject]@{
                Path="$root\$appId"; Name='RemovePackage'; Type='DWord'
                Value=[int]$legacyApps[$appId]; PolicyId=[string]$appId
                Description="Legacy v2.2.5 target: $appId"
            })
    }
    return [PSCustomObject]@{
        Root = $root
        Targets = @($targets)
        RemovalTargets = @($targets | Where-Object {
                $_.Name -eq 'RemovePackage' -and [int]$_.Value -eq 1
            })
    }
}
