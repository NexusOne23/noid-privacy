#Requires -Version 5.1

# Xbox sessions explicitly restore configuration only. App removal/recovery
# cannot promise an exact former package version or application data. Schema 4
# is separate from the unchanged schema-3 contract of the original nine actions.

function Test-NoIDXboxSessionTransientFile {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][IO.FileInfo]$File)

    # A killed atomic writer cannot clean up. These files are opaque evidence,
    # never an alternative manifest, state or receipt and never executed.
    if (-not $File.Exists -or ($File.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    if ($File.Name -cmatch '^(manifest|prestate|poststate)\.json\.[0-9a-f]{32}\.(?:tmp|replace-backup)$') {
        $limit = if ($Matches[1] -ceq 'manifest') { 65536 } else { 262144 }
        return $File.Length -le $limit
    }
    return Test-NoIDRestoreReceiptTransientFile -File $File
}

function New-NoIDXboxPreparedSession {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory)]$PreState,
        [Parameter(Mandatory)][ValidateSet('Enable','Disable')][string]$DesiredState,
        [string]$BackupDirectory = (Join-Path $script:FrameworkRoot 'Backups')
    )

    Assert-NoIDXboxActionState $PreState
    if ($PreState.state -ceq $DesiredState) { throw 'An unchanged Xbox state must not create a session' }
    if (-not $PSCmdlet.ShouldProcess($BackupDirectory, 'Record Xbox settings before changing apps and settings')) { return }
    $prepared = New-QuickActionPreparedSession -PreState $PreState -DesiredState $DesiredState -BackupDirectory $BackupDirectory -Confirm:$false
    $prepared.Manifest.schemaVersion = 4
    $prepared.Manifest['restoreMode'] = 'SettingsOnly'
    $null = Write-AtomicUtf8File -Path $prepared.ManifestPath -Content (ConvertTo-QuickActionCanonicalJson $prepared.Manifest)
    return $prepared
}

function Complete-NoIDXboxSession {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param([Parameter(Mandatory)]$PreparedSession, [Parameter(Mandatory)]$PostState)

    Assert-NoIDXboxObjectFields $PreparedSession @('SessionPath','ManifestPath','PrePath','Manifest')
    $root = [IO.Path]::GetFullPath([string]$PreparedSession.SessionPath).TrimEnd('\','/')
    if ([string]$PreparedSession.ManifestPath -cne (Join-Path $root 'manifest.json') -or
        [string]$PreparedSession.PrePath -cne (Join-Path $root 'prestate.json')) {
        throw 'Xbox prepared session contains an external output path'
    }
    Assert-NoIDXboxActionState $PostState
    $manifest = $PreparedSession.Manifest
    $preparedDocument = Get-NoIDXboxSessionDocument -SessionPath $PreparedSession.SessionPath -AllowPrepared
    if ($manifest.schemaVersion -ne 4 -or $manifest.actionId -cne 'Xbox' -or
        $manifest.restoreMode -cne 'SettingsOnly' -or $manifest.status -cne 'Prepared' -or
        $manifest.desiredState -cne $PostState.state -or
        (Get-QuickActionObjectSha256 $manifest) -cne (Get-QuickActionObjectSha256 $preparedDocument.Manifest) -or
        $PostState.targets.userSid -cne $preparedDocument.PreState.targets.userSid -or
        $PostState.targets.sessionId -ne $preparedDocument.PreState.targets.sessionId) {
        throw 'Xbox session cannot seal a different or incomplete operation'
    }
    if (-not $PSCmdlet.ShouldProcess($PreparedSession.SessionPath, 'Seal verified Xbox state with a settings-only restore contract')) { return }
    $null = Complete-QuickActionSession -PreparedSession $PreparedSession -PostState $PostState -Confirm:$false
    return Get-NoIDXboxSessionDocument -SessionPath $PreparedSession.SessionPath
}

function Get-NoIDXboxSessionDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath,

        [Parameter(Mandatory = $false)]
        $Manifest,

        [switch]$AllowPrepared,

        [switch]$AllowIncomplete
    )

    $sessionRoot = [System.IO.Path]::GetFullPath($SessionPath).TrimEnd('\', '/')
    $directory = Get-Item -LiteralPath $sessionRoot -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Xbox session root is not a real directory'
    }
    $manifestPath = Join-Path $sessionRoot 'manifest.json'
    $manifestFile = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
    if ($manifestFile.PSIsContainer -or ($manifestFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $manifestFile.Length -lt 2 -or $manifestFile.Length -gt 65536) {
        throw 'Xbox manifest is not a regular bounded file'
    }
    $diskManifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($Manifest -and (Get-QuickActionObjectSha256 $Manifest) -cne (Get-QuickActionObjectSha256 $diskManifest)) {
        throw 'Xbox supplied manifest differs from its on-disk record'
    }
    $Manifest = $diskManifest
    $required = @(
        'schemaVersion', 'recordType', 'sessionId', 'displayName', 'sessionType',
        'timestamp', 'frameworkVersion', 'actionId', 'owningModule',
        'desiredState', 'expectedPreFingerprint', 'preFingerprint',
        'postFingerprint', 'targetIds', 'status', 'restorable', 'artifacts', 'restoreMode'
    )
    $actual = @($Manifest.PSObject.Properties.Name)
    if ($actual.Count -ne $required.Count -or
        @(Compare-Object -ReferenceObject $required -DifferenceObject $actual).Count -ne 0) {
        throw 'Quick Action manifest has an unexpected field set'
    }
    $definition = [pscustomobject]@{OwningModule='SecurityBaseline';States=@('Enable','Disable')}
    $incompleteStatuses = @('Prepared','Rejected','ApplyFailedSettingsRestored','ApplyFailedSettingsRestoreFailed')
    $incomplete = $Manifest.status -cin $incompleteStatuses
    $hasPost = @($Manifest.artifacts | Where-Object role -CEQ poststate).Count -gt 0
    $allowedStatuses = if ($AllowPrepared) { @('Prepared') }
        elseif ($AllowIncomplete) { @('Applied') + $incompleteStatuses } else { @('Applied') }
    if ($Manifest.actionId -cne 'Xbox' -or $Manifest.restoreMode -cne 'SettingsOnly') {
        throw 'Xbox session has an invalid action or restore mode'
    }
    $sessionLeaf = Split-Path $sessionRoot -Leaf
    if ($sessionLeaf -cnotmatch '^Session_[0-9]{8}_[0-9]{6}_[0-9]{3}_[0-9a-f]{8}_QuickAction_Xbox$') {
        throw 'Xbox session directory identity is invalid'
    }
    if ($Manifest.schemaVersion -isnot [int] -or $Manifest.schemaVersion -ne 4 -or
        [string]$Manifest.recordType -cne 'QuickActionSession' -or
        [string]$Manifest.sessionId -cne $sessionLeaf -or
        [string]$Manifest.sessionType -cne 'quickAction' -or
        [string]$Manifest.owningModule -cne [string]$definition.OwningModule -or
        [string]$Manifest.desiredState -notin @($definition.States) -or
        [string]$Manifest.displayName -cne "Quick Action: $([string]$Manifest.actionId) -> $([string]$Manifest.desiredState)" -or
        [string]$Manifest.status -cnotin $allowedStatuses -or
        $Manifest.restorable -isnot [bool] -or $Manifest.restorable -eq $incomplete -or
        (-not $incomplete -and -not $hasPost) -or
        ($Manifest.status -cin @('Prepared','Rejected') -and $hasPost)) {
        throw 'Quick Action manifest identity/status is invalid or non-restorable'
    }
    $fingerprintProperties = @('expectedPreFingerprint', 'preFingerprint')
    if ($hasPost) { $fingerprintProperties += 'postFingerprint' }
    elseif ($Manifest.postFingerprint -cne '') { throw 'Prepared Xbox session has an invented poststate' }
    foreach ($fingerprintProperty in $fingerprintProperties) {
        if ([string]$Manifest.$fingerprintProperty -notmatch '^[0-9a-f]{64}$') {
            throw "Quick Action manifest has invalid $fingerprintProperty"
        }
    }
    if ([string]$Manifest.expectedPreFingerprint -cne [string]$Manifest.preFingerprint) {
        throw 'Quick Action manifest pre-fingerprint binding is inconsistent'
    }
    $null = ConvertFrom-NoIDRoundtripTimestamp `
        -Value $Manifest.timestamp `
        -Context 'Quick Action manifest'

    $artifacts = @($Manifest.artifacts)
    $artifactRoles = (@($artifacts.role | Sort-Object) -join "`0")
    $expectedRoles = @(if($hasPost){'poststate';'prestate'}else{'prestate'})
    if ($artifacts.Count -ne $expectedRoles.Count -or
        $artifactRoles -cne ($expectedRoles -join "`0")) {
        throw 'Quick Action manifest must contain exactly one prestate and one poststate artifact'
    }
    $allowedFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $null = $allowedFiles.Add([System.IO.Path]::GetFullPath((Join-Path $sessionRoot 'manifest.json')))
    $states = @{}
    foreach ($artifact in $artifacts) {
        $fields = @($artifact.PSObject.Properties.Name)
        if ($fields.Count -ne 3 -or
            @(Compare-Object -ReferenceObject @('role', 'relativePath', 'sha256') -DifferenceObject $fields).Count -ne 0 -or
            [string]$artifact.role -notin @('prestate', 'poststate') -or
            [string]$artifact.relativePath -cne "$([string]$artifact.role).json" -or
            [string]$artifact.sha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'Quick Action manifest contains an invalid artifact record'
        }
        $path = Resolve-SessionChildPath -SessionPath $sessionRoot -RelativePath ([string]$artifact.relativePath)
        $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($file.PSIsContainer -or $file.Length -lt 2 -or $file.Length -gt 262144 -or
            [bool]($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Quick Action artifact is not a real file: $path"
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($hash -cne [string]$artifact.sha256) {
            throw "Quick Action artifact integrity check failed: $path"
        }
        $state = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        Assert-NoIDXboxActionState -State $state
        $states[[string]$artifact.role] = $state
        $null = $allowedFiles.Add([System.IO.Path]::GetFullPath($path))
    }
    $pre = $states.prestate
    $post = if ($hasPost) { $states.poststate } else { $null }
    if ($pre.fingerprint -cne $Manifest.preFingerprint -or
        (@($pre.targetIds) -join "`0") -cne (@($Manifest.targetIds) -join "`0")) {
        throw 'Xbox manifest does not bind its exact prestate'
    }
    if ($hasPost -and ([string]$pre.actionId -cne [string]$Manifest.actionId -or
        [string]$post.actionId -cne [string]$Manifest.actionId -or
        [string]$pre.owningModule -cne [string]$Manifest.owningModule -or
        [string]$post.owningModule -cne [string]$Manifest.owningModule -or
        [string]$pre.fingerprint -cne [string]$Manifest.preFingerprint -or
        [string]$post.fingerprint -cne [string]$Manifest.postFingerprint -or
        [string]$post.state -cne [string]$Manifest.desiredState -or
        (@($pre.targetIds) -join "`0") -cne (@($Manifest.targetIds) -join "`0") -or
        (@($post.targetIds) -join "`0") -cne (@($Manifest.targetIds) -join "`0") -or
        $pre.targets.userSid -cne $post.targets.userSid -or
        $pre.targets.sessionId -ne $post.targets.sessionId)) {
        throw 'Quick Action manifest does not bind its exact state artifacts'
    }

    $unsealedPost = $null
    $postPath = Join-Path $sessionRoot 'poststate.json'
    if ($AllowIncomplete -and $Manifest.status -ceq 'Prepared' -and -not $hasPost -and
        (Test-Path -LiteralPath $postPath)) {
        $file = Get-Item -LiteralPath $postPath -Force -ErrorAction Stop
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $file.Length -lt 2 -or $file.Length -gt 262144) {
            throw 'Interrupted Xbox poststate is not a regular bounded file'
        }
        $candidate = Get-Content -LiteralPath $postPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        Assert-NoIDXboxActionState $candidate
        if ($candidate.targets.userSid -cne $pre.targets.userSid -or
            $candidate.targets.sessionId -ne $pre.targets.sessionId -or
            $candidate.state -cne $Manifest.desiredState) {
            throw 'Interrupted Xbox poststate has a different user or desired state'
        }
        # Only an explicitly failed record can adopt these observations. They
        # do not prove a successful Apply and are not a restore authorization.
        $unsealedPost = [pscustomobject]@{
            State=$candidate
            Artifact=[pscustomobject]@{
                role='poststate';relativePath='poststate.json'
                sha256=(Get-FileHash -LiteralPath $postPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
            }
        }
        $null = $allowedFiles.Add([IO.Path]::GetFullPath($postPath))
    }

    $receiptPath = Join-Path $sessionRoot 'restore-receipt.json'
    if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
        if ($Manifest.status -ceq 'Prepared') { throw 'A prepared Xbox session cannot contain a restore receipt' }
        $receipt = Get-SessionRestoreReceipt -SessionPath $sessionRoot -Manifest $Manifest
        $expectedScope = "action:$([string]$Manifest.actionId)"
        if (@($receipt.restoredScopes).Count -ne 1 -or
            [string]$receipt.restoredScopes[0] -cne $expectedScope) {
            throw 'Quick Action restore receipt does not contain its one exact action scope'
        }
        $null = $allowedFiles.Add([System.IO.Path]::GetFullPath($receiptPath))
    }
    foreach ($entry in @(Get-ChildItem -LiteralPath $sessionRoot -Force -ErrorAction Stop)) {
        if ($entry.PSIsContainer -or
            [bool]($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
            (-not $allowedFiles.Contains([System.IO.Path]::GetFullPath($entry.FullName)) -and
                -not (Test-NoIDXboxSessionTransientFile -File $entry))) {
            throw "Quick Action session contains an undeclared entry: $($entry.FullName)"
        }
    }

    return [PSCustomObject]@{
        Manifest = $Manifest
        PreState = $pre
        PostState = $post
        SessionPath = $sessionRoot
        UnsealedPost = $unsealedPost
    }
}

function Set-NoIDXboxFailedSession {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory)][string]$SessionPath,
        [Parameter(Mandatory)][ValidateSet('Rejected','ApplyFailedSettingsRestored','ApplyFailedSettingsRestoreFailed')][string]$Status
    )

    # Read and validate the actual files again. Never trust a mutable in-memory
    # manifest left behind by a failed completion write.
    $document = Get-NoIDXboxSessionDocument -SessionPath $SessionPath -AllowIncomplete
    if ($document.Manifest.status -cnotin @('Prepared','Applied')) {
        throw 'An Xbox failure record is already final'
    }
    if ($Status -ceq 'Rejected' -and $document.Manifest.status -cne 'Prepared') {
        throw 'A sealed Xbox change cannot be labelled as rejected before mutation'
    }
    if ($Status -ceq 'Rejected' -and $document.UnsealedPost) {
        throw 'Interrupted poststate evidence cannot be labelled as rejected before mutation'
    }
    if (-not $PSCmdlet.ShouldProcess($document.SessionPath, 'Record the Xbox failure without claiming app restoration')) { return }
    if ($document.UnsealedPost) {
        $document.Manifest.artifacts = @($document.Manifest.artifacts) + @($document.UnsealedPost.Artifact)
        $document.Manifest.postFingerprint = $document.UnsealedPost.State.fingerprint
    }
    $document.Manifest.status = $Status
    $document.Manifest.restorable = $false
    $null = Write-AtomicUtf8File -Path (Join-Path $document.SessionPath 'manifest.json') `
        -Content (ConvertTo-QuickActionCanonicalJson $document.Manifest)
    return Get-NoIDXboxSessionDocument -SessionPath $document.SessionPath -AllowIncomplete
}

function Get-NoIDXboxBackupSessionSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SessionPath)

    $document = Get-NoIDXboxSessionDocument -SessionPath $SessionPath -AllowIncomplete
    $manifest = $document.Manifest
    $receipt = Get-SessionRestoreReceipt -SessionPath $document.SessionPath -Manifest $manifest
    $closed = $receipt -and 'action:Xbox' -cin @($receipt.restoredScopes)
    $applied = $manifest.status -ceq 'Applied'
    $restorable = $false
    $settingsFingerprint = ''
    $validationStatus = 'IncompleteSession'
    $errorText = 'This Xbox operation did not complete. Its record does not promise app recovery or an exact app-data restore.'
    if ($closed) {
        $validationStatus = if ($applied) { 'RestoredAndValidated' } else { 'FailedSettingsClosed' }
        $errorText = if ($applied) { 'The recorded Xbox settings have already been restored; app installations were left unchanged.' }
            else { 'The failed Xbox operation has no outstanding settings rollback. App changes are separate.' }
    }
    else {
        try {
            # App updates do not invalidate a configuration-only restore. This
            # path reads settings only and never starts AppX or Store recovery.
            $comparison = Get-NoIDXboxSettingsComparison -Document $document
            $settingsFingerprint = Get-QuickActionObjectSha256 $comparison.CurrentSettings
            if ($applied -and -not $comparison.MatchesPre -and -not $comparison.MatchesPost) {
                $validationStatus = 'LiveStateDrifted'
                $errorText = 'Xbox settings differ from both recorded states; restore will refuse to overwrite them.'
            }
            else {
                Assert-NoIDXboxRestoreOrder -SelectedDocument $document
                Assert-NoIDXboxWorkersIdle
                $restorable = $true
                $validationStatus = if ($comparison.MatchesPre) { 'RestoreReceiptRepairAvailable' }
                    elseif ($applied) { 'SealedAndLivePoststateValidated' } else { 'InterruptedSettingsRecoveryAvailable' }
                $errorText = if ($comparison.MatchesPre) { 'The settings already match; restore will record completion without changing apps.' }
                    elseif (-not $applied) { 'Restore the recorded Xbox settings after this interrupted operation. Apps and their data will be left unchanged.' }
                    else { '' }
            }
        }
        catch { $validationStatus = 'LiveStateUnavailable'; $errorText = $_.Exception.Message }
    }
    $count = @(Get-NoIDXboxSettingsRegistryTargets).Count + (Get-NoIDXboxComponentCatalog).Services.Count + 1
    return [pscustomobject]@{
        SessionId=$manifest.sessionId
        DisplayName=$manifest.displayName + ' (settings only)'
        Timestamp=(ConvertFrom-NoIDRoundtripTimestamp -Value $manifest.timestamp -Context 'Xbox session')
        FrameworkVersion=$manifest.frameworkVersion
        SessionType='quickAction'
        RestoreMode='SettingsOnly'
        ExpectedSettingsFingerprint=$settingsFingerprint
        Modules=@([pscustomobject]@{
            name=$manifest.owningModule
            status=$(if ($applied -and $closed) {'Restored'} else {$manifest.status})
            itemsBackedUp=$count;actionId='Xbox';desiredState=$manifest.desiredState
        })
        TotalItems=$count
        Restorable=[bool]$restorable
        ValidationStatus=$validationStatus
        ValidationError=$errorText
        LastRestoredAt=$(if ($receipt) {ConvertFrom-NoIDRoundtripTimestamp -Value $receipt.completedAt -Context 'Xbox restore receipt'} else {$null})
        RestoredModules=@(if ($closed -and $applied) {$manifest.owningModule})
        RetentionKind=$(if (-not $applied) {'QuickActionFailed'} elseif ($closed) {'QuickActionRestored'} else {'QuickActionSealed'})
        SessionPath=$document.SessionPath
        FolderPath=$document.SessionPath
    }
}
