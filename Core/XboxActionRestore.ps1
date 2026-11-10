#Requires -Version 5.1

function Get-NoIDXboxSettingsComparison {
    <# Apps remain untouched by a settings-only restore, including newer Store versions. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Document)

    $user = Get-PrivacyUserContext -Refresh
    if ($user.Sid -cne $Document.PreState.targets.userSid) {
        throw 'Xbox settings restore belongs to a different desktop user'
    }
    $null = Assert-NoIDXboxUnmanagedDevice
    $live = Get-NoIDXboxSettingsState
    $hash = Get-QuickActionObjectSha256 $live
    return [pscustomobject]@{
        CurrentSettings=$live
        MatchesPre=($hash -ceq (Get-QuickActionObjectSha256 $Document.PreState.targets.settings))
        MatchesPost=($null -ne $Document.PostState -and $hash -ceq (Get-QuickActionObjectSha256 $Document.PostState.targets.settings))
    }
}

function Assert-NoIDXboxRestoreOrder {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$SelectedDocument, [string[]]$ModuleNames=@())

    if ($ModuleNames.Count -gt 0 -and @($ModuleNames | Where-Object { $_ -in @('Privacy','SecurityBaseline') }).Count -eq 0) { return }
    $root = Split-Path $SelectedDocument.SessionPath -Parent
    foreach ($folder in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop)) {
        if ($folder.FullName -ceq $SelectedDocument.SessionPath) { continue }
        if ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        $path = Join-Path $folder.FullName 'manifest.json'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $candidate = $null
        try {
            $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            $candidate = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch { continue }
        $scopes = @()
        if ($candidate.PSObject.Properties['recordType'] -and $candidate.recordType -ceq 'QuickActionSession' -and
            $candidate.PSObject.Properties['actionId'] -and $candidate.actionId -ceq 'Xbox') {
            # Prepared and failed Xbox changes can also have left app/settings
            # changes. Only a validated receipt can dismiss a newer one here.
            $scopes = @('action:Xbox')
        }
        elseif ($ModuleNames.Count -eq 0 -and $candidate.PSObject.Properties['schemaVersion'] -and [int]$candidate.schemaVersion -eq 2 -and
            $candidate.PSObject.Properties['modules']) {
            $scopes = @($candidate.modules | Where-Object { $_.name -in @('SecurityBaseline','Privacy') } |
                ForEach-Object { 'module:'+ $_.name })
        }
        if ($scopes.Count -eq 0) { continue }
        try {
            $null = ConvertFrom-NoIDRoundtripTimestamp -Value $candidate.timestamp -Context 'Overlapping Xbox restore candidate'
            if (-not (Test-QuickActionManifestIsNewer -Candidate $candidate -Selected $SelectedDocument.Manifest)) { continue }
            $receipt = Get-SessionRestoreReceipt -SessionPath $folder.FullName -Manifest $candidate
            foreach ($scope in $scopes) {
                $completed = $receipt -and $(if ($scope.StartsWith('module:', [StringComparison]::Ordinal)) {
                    $scope -in @($receipt.restoredScopes)
                } else { $scope -cin @($receipt.restoredScopes) })
                if (-not $completed) {
                    throw 'A newer overlapping Xbox, Privacy or SecurityBaseline change must be restored first'
                }
            }
        }
        catch { throw ('Xbox restore order cannot be verified: '+$_.Exception.Message) }
    }
}

function Restore-NoIDXboxActionSettings {
    <# The transaction owner holds the mutation lock and supplies its verified current settings. #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([Parameter(Mandatory)]$Settings, [Parameter(Mandatory)]$ExpectedCurrentSettings)

    Assert-NoIDXboxSettingsState $Settings
    Assert-NoIDXboxSettingsState $ExpectedCurrentSettings
    $live = Get-NoIDXboxSettingsState
    if ((Get-QuickActionObjectSha256 $live) -cne (Get-QuickActionObjectSha256 $ExpectedCurrentSettings)) {
        throw 'Xbox settings changed before restore; refusing to overwrite the newer state'
    }
    if (-not $PSCmdlet.ShouldProcess('Xbox settings', 'Restore recorded configuration; keep app installations unchanged')) { return $false }
    Restore-NoIDXboxSettingsState -State $Settings -Confirm:$false
    $restored = Get-NoIDXboxSettingsState
    if ((Get-QuickActionObjectSha256 $restored) -cne (Get-QuickActionObjectSha256 $Settings)) {
        throw 'Xbox settings restore did not match the recorded configuration'
    }
    return $true
}

function Restore-NoIDXboxSession {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$SessionPath,
        [ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSettingsFingerprint
    )

    $mutex = [Threading.Mutex]::new($false, $script:NoIDMutationMutexName)
    $held = $false
    try {
        try { $held = $mutex.WaitOne(0, $false) }
        catch [Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'Another NoID mutation is already running' }
        $document = Get-NoIDXboxSessionDocument -SessionPath $SessionPath -AllowIncomplete
        $receipt = Get-SessionRestoreReceipt -SessionPath $document.SessionPath -Manifest $document.Manifest
        if ($receipt -and 'action:Xbox' -cin @($receipt.restoredScopes)) { return $true }
        Assert-NoIDXboxWorkersIdle
        Assert-NoIDXboxRestoreOrder -SelectedDocument $document
        $comparison = Get-NoIDXboxSettingsComparison -Document $document
        $incomplete = $document.Manifest.status -cne 'Applied'
        $currentHash = Get-QuickActionObjectSha256 $comparison.CurrentSettings
        if ($ExpectedSettingsFingerprint -and $currentHash -cne $ExpectedSettingsFingerprint) {
            throw 'Xbox settings changed after recovery was displayed; refresh before restoring'
        }
        if ($incomplete -and -not $comparison.MatchesPre -and -not $ExpectedSettingsFingerprint) {
            throw 'Interrupted Xbox settings recovery requires the reviewed current settings fingerprint'
        }
        if (-not $incomplete -and -not $comparison.MatchesPre -and -not $comparison.MatchesPost) {
            throw 'Current Xbox settings differ from both recorded states; refusing to overwrite newer settings'
        }
        if (-not $PSCmdlet.ShouldProcess($document.SessionPath, 'Restore Xbox settings only; apps and their data are not restored')) { return $false }
        if ($document.Manifest.status -ceq 'Prepared') {
            # Finalize the interrupted operation as failed, retaining all valid
            # observations. Only the explicit reviewed settings snapshot above
            # can authorize recovery; an unsealed poststate cannot do so.
            $document = Set-NoIDXboxFailedSession -SessionPath $document.SessionPath `
                -Status ApplyFailedSettingsRestoreFailed -Confirm:$false
        }
        $changed = $false
        $receiptUncertain = $false
        try {
            if (-not $comparison.MatchesPre) {
                $changed = $true
                $null = Restore-NoIDXboxActionSettings -Settings $document.PreState.targets.settings `
                    -ExpectedCurrentSettings $comparison.CurrentSettings -Confirm:$false
            }
            try {
                $null = Write-SessionRestoreReceipt -SessionPath $document.SessionPath -Manifest $document.Manifest `
                    -Scopes @('action:Xbox') -Confirm:$false
            }
            catch {
                $publicationError = $_.Exception.Message
                $validated = $null
                try { $validated = Get-SessionRestoreReceipt -SessionPath $document.SessionPath -Manifest $document.Manifest }
                catch { $validated = $null }
                if ($validated -and 'action:Xbox' -cin @($validated.restoredScopes)) {
                    $null = Update-NoIDXboxIntentAfterChange -SourceKind QuickActionRestore -SessionPath $document.SessionPath
                    return $true
                }
                $receiptPath = Join-Path $document.SessionPath 'restore-receipt.json'
                try {
                    if (Test-Path -LiteralPath $receiptPath) {
                        $file = Get-Item -LiteralPath $receiptPath -Force -ErrorAction Stop
                        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                            throw 'Receipt candidate is not a regular file'
                        }
                        Remove-Item -LiteralPath $receiptPath -Force -ErrorAction Stop
                    }
                    if (Test-Path -LiteralPath $receiptPath) { throw 'Receipt candidate remained after cleanup' }
                }
                catch { $receiptUncertain = $true; throw ('Xbox restore receipt could not be safely resolved: '+$publicationError) }
                throw ('Xbox restore receipt publication failed: '+$publicationError)
            }
        }
        catch {
            $failure = $_.Exception.Message
            if ($changed -and -not $receiptUncertain) {
                try {
                    $live = Get-NoIDXboxSettingsState
                    $liveHash = Get-QuickActionObjectSha256 $live
                    if ($liveHash -cne (Get-QuickActionObjectSha256 $comparison.CurrentSettings)) {
                        if ($liveHash -cne (Get-QuickActionObjectSha256 $document.PreState.targets.settings)) {
                            throw 'The partial or externally changed settings cannot be safely compensated automatically'
                        }
                        $null = Restore-NoIDXboxActionSettings -Settings $comparison.CurrentSettings -ExpectedCurrentSettings $live -Confirm:$false
                    }
                }
                catch { throw ($failure+' Settings compensation also failed: '+$_.Exception.Message) }
            }
            if ($receiptUncertain) { throw ($failure+' The restored settings were retained because receipt status is uncertain') }
            throw $failure
        }
        $null = Update-NoIDXboxIntentAfterChange -SourceKind QuickActionRestore -SessionPath $document.SessionPath
        return $true
    }
    finally {
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}
