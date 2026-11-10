#Requires -Version 5.1

function Get-PrivacyTier1Schema7RestorePolicyDefinition {
    <#
    .SYNOPSIS
        Returns the frozen PFN-based Tier 1 identity contract for schema 4-7 restore.

    .DESCRIPTION
        Restore validation must remain independent of the current Apply config.
        This closed inventory is the contract already emitted by NoID Privacy
        2.2.5 schema 4-7 snapshots. Any future Apply inventory change requires a
        new snapshot schema and a separate frozen restore definition.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages'
    $pfns = @(
        'Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe'
        'Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe'
        'Clipchamp.Clipchamp_yxz26nhyzhsrt'
        'Microsoft.Copilot_8wekyb3d8bbwe'
        'Microsoft.BingNews_8wekyb3d8bbwe'
        'Microsoft.Windows.Photos_8wekyb3d8bbwe'
        'Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe'
        'Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe'
        'MSTeams_8wekyb3d8bbwe'
        'Microsoft.Todos_8wekyb3d8bbwe'
        'Microsoft.BingWeather_8wekyb3d8bbwe'
        'Microsoft.OutlookForWindows_8wekyb3d8bbwe'
        'Microsoft.Paint_8wekyb3d8bbwe'
        'MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe'
        'Microsoft.ScreenSketch_8wekyb3d8bbwe'
        'Microsoft.WindowsCalculator_8wekyb3d8bbwe'
        'Microsoft.WindowsCamera_8wekyb3d8bbwe'
        'Microsoft.ZuneMusic_8wekyb3d8bbwe'
        'Microsoft.WindowsNotepad_8wekyb3d8bbwe'
        'Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe'
        'Microsoft.WindowsTerminal_8wekyb3d8bbwe'
        'Microsoft.GamingApp_8wekyb3d8bbwe'
        'Microsoft.XboxIdentityProvider_8wekyb3d8bbwe'
        'Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe'
        'Microsoft.Xbox.TCUI_8wekyb3d8bbwe'
    )
    $targets = [Collections.Generic.List[object]]::new()
    $targets.Add([PSCustomObject]@{ Path=$root; Name='Enabled' })
    $targets.Add([PSCustomObject]@{ Path=$root; Name='DynamicRemovalList' })
    foreach ($pfn in $pfns) {
        $targets.Add([PSCustomObject]@{ Path="$root\$pfn"; Name='RemovePackage' })
    }
    if ($targets.Count -ne 27) {
        throw 'Frozen Privacy schema 4-7 Tier 1 restore contract is incomplete'
    }
    return [PSCustomObject]@{ Contract='Schema4To7PFN'; Targets=@($targets) }
}

function Get-PrivacyTier1LegacyV225RestorePolicyDefinition {
    <#
    .SYNOPSIS
        Returns the frozen symbolic-ID Tier 1 identity contract for legacy restore.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages'
    $ids = @(
        'WindowsFeedbackHub','MicrosoftOfficeHub','Clipchamp','Copilot','BingNews','Photos',
        'MicrosoftSolitaireCollection','MicrosoftStickyNotes','MSTeams','Todo','BingWeather',
        'OutlookForWindows','Paint','QuickAssist','ScreenSketch','WindowsCalculator',
        'WindowsCamera','MediaPlayer','WindowsNotepad','WindowsSoundRecorder','WindowsTerminal',
        'GamingApp','XboxGamingOverlay','XboxIdentityProvider','XboxSpeechToTextOverlay','XboxTCUI'
    )
    $targets = [Collections.Generic.List[object]]::new()
    $targets.Add([PSCustomObject]@{ Path=$root; Name='Enabled' })
    foreach ($id in $ids) {
        $targets.Add([PSCustomObject]@{ Path="$root\$id"; Name='RemovePackage' })
    }
    if ($targets.Count -ne 27) {
        throw 'Frozen Privacy legacy v2.2.5 Tier 1 restore contract is incomplete'
    }
    return [PSCustomObject]@{ Contract='LegacyV225Symbolic'; Targets=@($targets) }
}
