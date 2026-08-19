<#
.SYNOPSIS
    Durable, machine-local Apply intent for standalone live verification.

.DESCRIPTION
    This record is deliberately separate from BAVR sessions. It labels which
    exact optional/profile choices a successful Apply requested, while every
    compliance result continues to come from live Windows state. Deleting a
    backup therefore cannot redirect verification. Missing, corrupt, or
    schema-incompatible intent is fail-visible and is never replaced by defaults.
    The engine hash is retained as provenance, not used as a false compatibility
    oracle for otherwise schema-valid intent after a reviewed engine update.
#>

$script:NoIDIntentStateSchema = 3
$script:NoIDIntentModuleNames = @(
    'SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI',
    'EdgeHardening', 'AdvancedSecurity'
)

function Get-NoIDIntentStatePath {
    [CmdletBinding()]
    param()

    $commonApplicationData = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonApplicationData
    )
    if ([string]::IsNullOrWhiteSpace([string]$commonApplicationData) -or
        -not [System.IO.Path]::IsPathRooted([string]$commonApplicationData)) {
        throw 'ProgramData is unavailable; durable Apply intent cannot be stored'
    }
    return (Join-Path $commonApplicationData 'NoID Privacy\EngineState\last-apply-intent.json')
}

function Set-NoIDIntentPathSecurity {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Internal fail-closed ACL primitive; callers own confirmation and this helper must never prompt.'
    )]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][bool]$IsDirectory
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Apply-intent path must not be a reparse point: $Path"
    }

    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $security = if ($IsDirectory) {
        [Security.AccessControl.DirectorySecurity]::new()
    }
    else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($administratorsSid)
    $inheritance = if ($IsDirectory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow
            ))
    }
    Set-Acl -LiteralPath $Path -AclObject $security -ErrorAction Stop
}

function Initialize-NoIDIntentStateDirectory {
    [CmdletBinding()]
    param()

    $statePath = Get-NoIDIntentStatePath
    $stateDirectory = Split-Path $statePath -Parent
    $productDirectory = Split-Path $stateDirectory -Parent
    foreach ($directory in @($productDirectory, $stateDirectory)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
        }
        $item = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Apply-intent path component must not be a reparse point: $directory"
        }
    }
    # Reclaim both directories even if an unprivileged account pre-created
    # either one. Replacing only the DACL is insufficient while that account
    # remains owner and therefore retains the ability to grant itself WRITE_DAC.
    Set-NoIDIntentPathSecurity -Path $productDirectory -IsDirectory $true
    Set-NoIDIntentPathSecurity -Path $stateDirectory -IsDirectory $true
    return $stateDirectory
}

function Assert-NoIDIntentStateAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$StatePath)

    $allowedWriterSids = @('S-1-5-18', 'S-1-5-32-544')
    $stateDirectory = Split-Path $StatePath -Parent
    $productDirectory = Split-Path $stateDirectory -Parent
    foreach ($path in @($productDirectory, $stateDirectory, $StatePath)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Apply-intent path must not be a reparse point: $path"
        }
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        $ownerSid = [string]$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($ownerSid -notin $allowedWriterSids) {
            throw "Apply-intent path has an untrusted owner: $ownerSid ($path)"
        }
        if (-not $acl.AreAccessRulesProtected) {
            throw "Apply-intent ACL inheritance is not disabled: $path"
        }
        $rules = $acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        )
        foreach ($rule in @($rules)) {
            if ([string]$rule.AccessControlType -ne 'Allow') { continue }
            # Composite rights such as FullControl and Modify contain read
            # bits. Build the mask only from atomic mutation/DACL rights so a
            # normal ReadAndExecute ACE is not misclassified as writable.
            $writeMask = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
                [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                [System.Security.AccessControl.FileSystemRights]::Delete -bor
                [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                [System.Security.AccessControl.FileSystemRights]::TakeOwnership
            # FileSystemRights may preserve the Win32 GENERIC_WRITE / GENERIC_ALL
            # bits instead of expanding them into the specific file rights.
            # Treat those raw bits as mutation rights as well.
            $rightsValue = [uint32]([int64]$rule.FileSystemRights -band 0xffffffffL)
            $genericMutationMask = [uint32]0x50000000
            if ((($rule.FileSystemRights -band $writeMask) -ne 0 -or
                    ($rightsValue -band $genericMutationMask) -ne 0) -and
                [string]$rule.IdentityReference.Value -notin $allowedWriterSids) {
                throw "Apply-intent path grants write access to an untrusted identity: $($rule.IdentityReference.Value)"
            }
        }
    }
    return $true
}

function Publish-NoIDIntentState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$State)

    # Validate the exact object that will be published. A writer must never
    # atomically replace the last good record and discover schema corruption
    # only afterwards.
    $json = $State | ConvertTo-Json -Depth 20
    $roundTrip = $json | ConvertFrom-Json -ErrorAction Stop
    $null = Assert-NoIDIntentState -State $roundTrip

    $stateDirectory = Initialize-NoIDIntentStateDirectory
    $statePath = Join-Path $stateDirectory 'last-apply-intent.json'
    if (Test-Path -LiteralPath $statePath) {
        $existing = Get-Item -LiteralPath $statePath -Force -ErrorAction Stop
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Apply-intent path must not be a reparse point: $statePath"
        }
        # File.Replace preserves the destination DACL. Reclaim an existing
        # candidate before replacement so no attacker-supplied writable ACL is
        # live during the publication step.
        Set-NoIDIntentPathSecurity -Path $statePath -IsDirectory $false
    }
    $null = Write-AtomicUtf8File -Path $statePath -Content $json
    Set-NoIDIntentPathSecurity -Path $statePath -IsDirectory $false
    $null = Assert-NoIDIntentStateAcl -StatePath $statePath
    return $statePath
}

function Get-NoIDEngineContractFingerprint {
    [CmdletBinding()]
    param()

    $root = [System.IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent)).TrimEnd('\', '/')
    $excludedRoots = @('Backups', 'Logs', 'Reports', '.git')
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($root)
    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            $relative = $item.FullName.Substring($root.Length).TrimStart('\', '/')
            $top = @($relative -split '[\\/]', 2)[0]
            if ($top -in $excludedRoots) { continue }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Engine contract contains a reparse point: $relative"
            }
            if ($item.PSIsContainer) {
                $pending.Enqueue($item.FullName)
                continue
            }
            $extensionIncluded = $item.Extension -in @('.ps1', '.psm1', '.psd1', '.json', '.inf')
            $specialIncluded = $item.Name -ceq 'VERSION'
            if ($relative -cne 'config.json' -and ($extensionIncluded -or $specialIncluded)) {
                $files.Add([System.IO.FileInfo]$item)
            }
        }
    }
    $files = @($files | Sort-Object FullName)
    if ($files.Count -lt 1) { throw 'Engine contract fingerprint has no input files' }

    $builder = [System.Text.StringBuilder]::new()
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $null = $builder.Append($relative).Append([char]0).Append($file.Length).Append([char]0).Append($hash).Append("`n")
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Assert-NoIDIntentExactProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    $actual = @($Object.PSObject.Properties.Name)
    $missing = @($Expected | Where-Object { $_ -cnotin $actual })
    $unknown = @($actual | Where-Object { $_ -cnotin $Expected })
    if ($missing.Count -gt 0 -or $unknown.Count -gt 0) {
        throw "$Label property contract mismatch (missing: $($missing -join ', '); unknown: $($unknown -join ', '))"
    }
    return $true
}

function Assert-NoIDIntentUtcTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    # PowerShell 7.5+ materializes ISO JSON timestamps as DateTime while
    # Windows PowerShell 5.1 keeps the original string. Accept the former only
    # when it is already unambiguously UTC; the string path below retains the
    # canonical wire-format check used by the Windows engine.
    if ($Value -is [datetime]) {
        if ($Value.Kind -ne [DateTimeKind]::Utc) {
            throw "$Label must be a canonical UTC round-trip timestamp"
        }
        return $true
    }
    $text = [string]$Value

    $parsed = [datetime]::MinValue
    $valid = [datetime]::TryParseExact(
        $text,
        'o',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsed
    )
    if (-not $valid -or $parsed.Kind -ne [DateTimeKind]::Utc -or -not $text.EndsWith('Z', [StringComparison]::Ordinal)) {
        throw "$Label must be a canonical UTC round-trip timestamp"
    }
    return $true
}

function Assert-NoIDIntentState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$State)

    $null = Assert-NoIDIntentExactProperties -Object $State -Expected @(
        'schemaVersion','frameworkVersion','engineContractFingerprint','updatedAt','modules'
    ) -Label 'Apply-intent root'
    if ([int]$State.schemaVersion -notin @(2, $script:NoIDIntentStateSchema)) {
        throw "Unsupported Apply-intent schema: $($State.schemaVersion)"
    }
    if ([string]$State.frameworkVersion -notmatch '^\d+\.\d+\.\d+$') {
        throw 'Apply-intent frameworkVersion is invalid'
    }
    if ([string]$State.engineContractFingerprint -notmatch '^[0-9a-f]{64}$') {
        throw 'Apply-intent engineContractFingerprint is invalid'
    }
    $null = Assert-NoIDIntentUtcTimestamp -Value $State.updatedAt -Label 'Apply-intent updatedAt'
    if ($null -eq $State.modules) { throw 'Apply-intent modules object is missing' }
    $moduleProperties = @($State.modules.PSObject.Properties)
    $unknown = @($moduleProperties.Name | Where-Object { $_ -cnotin $script:NoIDIntentModuleNames })
    if ($unknown.Count -gt 0) { throw "Apply-intent contains unknown modules: $($unknown -join ', ')" }
    foreach ($moduleProperty in $moduleProperties) {
        $record = $moduleProperty.Value
        $null = Assert-NoIDIntentExactProperties -Object $record -Expected @(
            'moduleName','recordedAt','sourceKind','sourceId','sourceEvidenceSha256','intent'
        ) -Label "Apply-intent module record $($moduleProperty.Name)"
        if ([string]$record.moduleName -cne [string]$moduleProperty.Name) {
            throw "Apply-intent module identity mismatch: $($moduleProperty.Name)"
        }
        $null = Assert-NoIDIntentUtcTimestamp -Value $record.recordedAt `
            -Label "Apply-intent recordedAt for $($moduleProperty.Name)"
        if ([string]$record.sourceKind -notin @(
                'ApplySession', 'ApplyDecision', 'QuickActionApply', 'QuickActionRestore',
                'QuickActionLiveConfirmation'
            )) {
            throw "Apply-intent decision source kind is invalid: $($moduleProperty.Name)"
        }
        if ([string]::IsNullOrWhiteSpace([string]$record.sourceId)) {
            throw "Apply-intent decision source ID is invalid: $($moduleProperty.Name)"
        }
        if ([string]$record.sourceKind -eq 'ApplySession' -and
            [string]$record.sourceId -notmatch '^Session_\d{8}_\d{6}_\d{3}_[0-9a-f]{8}$') {
            throw "Apply-intent Apply-session ID is invalid: $($moduleProperty.Name)"
        }
        if ([string]$record.sourceKind -in @('QuickActionApply', 'QuickActionRestore') -and
            [string]$record.sourceId -notmatch '^Session_\d{8}_\d{6}_\d{3}_[0-9a-f]{8}_QuickAction_[A-Za-z]+$') {
            throw "Apply-intent Quick Action session ID is invalid: $($moduleProperty.Name)"
        }
        if ([string]$record.sourceEvidenceSha256 -notmatch '^[0-9a-f]{64}$') {
            throw "Apply-intent decision evidence hash is invalid: $($moduleProperty.Name)"
        }
        if ($null -eq $record.intent) { throw "Apply-intent decision object is missing: $($moduleProperty.Name)" }
        $intent = $record.intent
        $requireBoolean = {
            param([string]$Name)
            $property = $intent.PSObject.Properties[$Name]
            if (-not $property -or $property.Value -isnot [bool]) {
                throw "Apply-intent Boolean decision is missing or invalid: $($moduleProperty.Name).$Name"
            }
        }
        switch ([string]$moduleProperty.Name) {
            'SecurityBaseline' {
                $null = Assert-NoIDIntentExactProperties -Object $intent -Expected @(
                    'standardUserElevationMode','bitLockerUSBEnforcement','submitAllSamples',
                    'smartScreenWarnMode','asrActionOverrides'
                ) -Label 'Apply-intent SecurityBaseline decision'
                if ([string]$intent.standardUserElevationMode -notin @('Strict','SecureDesktop')) {
                    throw 'Apply-intent SecurityBaseline.standardUserElevationMode is invalid'
                }
                foreach ($name in @('bitLockerUSBEnforcement','submitAllSamples','smartScreenWarnMode')) {
                    & $requireBoolean $name
                }
                $overrides = @($intent.asrActionOverrides)
                $seenOverrides = @{}
                foreach ($override in $overrides) {
                    $null = Assert-NoIDIntentExactProperties -Object $override -Expected @('Guid','Action') `
                        -Label 'Apply-intent SecurityBaseline ASR override'
                    $guid = ([Guid]([string]$override.Guid)).ToString('D').ToLowerInvariant()
                    if ($seenOverrides.ContainsKey($guid) -or [int]$override.Action -notin @(0,1,2,6)) {
                        throw "Apply-intent SecurityBaseline ASR override is duplicate or invalid: $guid"
                    }
                    $seenOverrides[$guid] = $true
                }
            }
            'ASR' {
                $null = Assert-NoIDIntentExactProperties -Object $intent -Expected @('requestedActions') `
                    -Label 'Apply-intent ASR decision'
                $actions = @($intent.requestedActions)
                if ($actions.Count -lt 1) { throw 'Apply-intent ASR requestedActions is empty' }
                $seenActions = @{}
                foreach ($actionRecord in $actions) {
                    $null = Assert-NoIDIntentExactProperties -Object $actionRecord -Expected @('Guid','Action') `
                        -Label 'Apply-intent ASR action'
                    $guid = ([Guid]([string]$actionRecord.Guid)).ToString('D').ToLowerInvariant()
                    if ($seenActions.ContainsKey($guid) -or [int]$actionRecord.Action -notin @(0,1,2,6)) {
                        throw "Apply-intent ASR action is duplicate or invalid: $guid"
                    }
                    $seenActions[$guid] = $true
                }
            }
            'DNS' {
                $null = Assert-NoIDIntentExactProperties -Object $intent -Expected @('provider','dohMode') `
                    -Label 'Apply-intent DNS decision'
                $provider = [string]$intent.provider
                $dohMode = [string]$intent.dohMode
                $providerModeValid = ($provider -in @('Quad9','Cloudflare','AdGuard') -and
                    $dohMode -in @('REQUIRE','ALLOW'))
                $keepValid = ($provider -ceq 'KEEP' -and $dohMode -ceq 'KEEP')
                if (-not ($providerModeValid -or $keepValid)) {
                    throw 'Apply-intent DNS decision is invalid'
                }
            }
            'Privacy' {
                $null = Assert-NoIDIntentExactProperties -Object $intent -Expected @(
                    'mode','disableCloudClipboard','applyStorePackagePolicy',
                    'removeBloatwareApps','removeWeatherWidget'
                ) -Label 'Apply-intent Privacy decision'
                if ([string]$intent.mode -notin @('MSRecommended','Strict','Paranoid')) {
                    throw 'Apply-intent Privacy mode is invalid'
                }
                foreach ($name in @(
                        'disableCloudClipboard','applyStorePackagePolicy',
                        'removeBloatwareApps','removeWeatherWidget'
                    )) { & $requireBoolean $name }
            }
            'AntiAI' {
                if ([int]$State.schemaVersion -eq 2) {
                    $null = Assert-NoIDIntentExactProperties -Object $intent -Expected @() `
                        -Label 'Apply-intent AntiAI legacy decision'
                }
                else {
                    $null = Assert-NoIDIntentExactProperties -Object $intent -Expected @(
                        'applicableTargets','notApplicableTargets'
                    ) -Label 'Apply-intent AntiAI decision'
                    $seenAntiAI = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    foreach ($bucketName in @('applicableTargets','notApplicableTargets')) {
                        foreach ($targetIdentity in @($intent.$bucketName)) {
                            $null = Assert-NoIDIntentExactProperties -Object $targetIdentity -Expected @('path','name') `
                                -Label "Apply-intent AntiAI $bucketName identity"
                            $path = [string]$targetIdentity.path
                            $name = [string]$targetIdentity.name
                            if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($name) -or
                                -not $seenAntiAI.Add("$path`0$name")) {
                                throw 'Apply-intent AntiAI target identity is empty or duplicated'
                            }
                        }
                    }
                    if ($seenAntiAI.Count -ne 43) {
                        throw "Apply-intent AntiAI plan must contain exactly 43 target identities; got $($seenAntiAI.Count)"
                    }
                }
            }
            'EdgeHardening' {
                $null = Assert-NoIDIntentExactProperties -Object $intent -Expected @('allowExtensions') `
                    -Label 'Apply-intent EdgeHardening decision'
                & $requireBoolean 'allowExtensions'
            }
            'AdvancedSecurity' {
                $null = Assert-NoIDIntentExactProperties -Object $intent -Expected @(
                    'securityProfile','skipFirewallLayer','disableRDP','adminSharesDisabled','disableUPnP',
                    'disableWirelessDisplay','disableDiscoveryProtocols','disableIPv6','enableFirewallShieldsUp'
                ) -Label 'Apply-intent AdvancedSecurity decision'
                if ([string]$intent.securityProfile -notin @('Balanced','Enterprise','Maximum')) {
                    throw 'Apply-intent AdvancedSecurity profile is invalid'
                }
                foreach ($name in @(
                        'skipFirewallLayer','disableRDP','adminSharesDisabled','disableUPnP',
                        'disableWirelessDisplay','disableDiscoveryProtocols','disableIPv6',
                        'enableFirewallShieldsUp'
                    )) { & $requireBoolean $name }
            }
        }
    }
    return $true
}

function Read-NoIDIntentState {
    [CmdletBinding()]
    param([switch]$AllowMissing)

    $statePath = Get-NoIDIntentStatePath
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        if ($AllowMissing) { return $null }
        throw "Apply-intent record is missing: $statePath"
    }
    $null = Assert-NoIDIntentStateAcl -StatePath $statePath
    $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $null = Assert-NoIDIntentState -State $state
    return $state
}

function New-NoIDModuleIntent {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Pure in-memory constructor; despite the New verb it does not mutate system state.'
    )]
    param([Parameter(Mandatory)][object]$ModuleResult)

    $moduleName = [string]$ModuleResult.ModuleName
    switch ($moduleName) {
        'SecurityBaseline' {
            $details = $ModuleResult.Details
            # The Apply itself may have aligned the PSExec/WMI ASR rule with a
            # recorded user decision (Invoke-SecurityBaseline Step 5). Carrying
            # that decision here keeps the rewritten SecurityBaseline record
            # self-consistent for baseline-scoped verification; an empty array
            # remains the shape for "sealed package value used".
            $overrides = @()
            foreach ($override in @($details.AsrActionOverrides | Where-Object { $null -ne $_ })) {
                $overrideAction = [int]$override.Action
                if ($overrideAction -notin @(1, 2)) {
                    throw "SecurityBaseline result carries an unsupported ASR override action: $overrideAction"
                }
                $overrides += [PSCustomObject]@{
                    Guid = ([Guid]([string]$override.Guid)).ToString('D').ToLowerInvariant()
                    Action = $overrideAction
                }
            }
            return [ordered]@{
                standardUserElevationMode = [string]$details.StandardUserElevationMode
                bitLockerUSBEnforcement = [bool]$details.BitLockerUSBEnforcement
                submitAllSamples = [bool]$details.SubmitAllSamples
                smartScreenWarnMode = [bool]$details.SmartScreenWarnMode
                asrActionOverrides = @($overrides)
            }
        }
        'ASR' {
            $actions = @($ModuleResult.Details.RequestedActions)
            if ($actions.Count -lt 1) { throw 'ASR result has no requested-action plan' }
            return [ordered]@{ requestedActions = @($actions) }
        }
        'DNS' {
            $provider = [string]$ModuleResult.Provider
            $dohMode = [string]$ModuleResult.DoHMode
            $providerModeValid = ($provider -in @('Quad9', 'Cloudflare', 'AdGuard') -and
                $dohMode -in @('REQUIRE', 'ALLOW'))
            $keepValid = ($provider -ceq 'KEEP' -and $dohMode -ceq 'KEEP')
            if (-not ($providerModeValid -or $keepValid)) {
                throw 'A DNS result has an invalid provider or DoH mode'
            }
            return [ordered]@{ provider = $provider; dohMode = $dohMode }
        }
        'Privacy' {
            if ([string]$ModuleResult.Mode -notin @('MSRecommended', 'Strict', 'Paranoid')) {
                throw 'A successful Privacy result has an invalid mode'
            }
            return [ordered]@{
                mode = [string]$ModuleResult.Mode
                disableCloudClipboard = [bool]$ModuleResult.DisableCloudClipboard
                applyStorePackagePolicy = [bool]$ModuleResult.Tier1PolicyRemovalSelected
                removeBloatwareApps = [bool]$ModuleResult.Tier2BloatwareRemovalSelected
                removeWeatherWidget = [bool]$ModuleResult.WeatherWidgetRemovalSelected
            }
        }
        'AntiAI' {
            $applicable = @($ModuleResult.ApplicableTargetPlan)
            $notApplicable = @($ModuleResult.NotApplicableTargetPlan)
            if ($applicable.Count + $notApplicable.Count -ne 43) {
                throw 'A successful AntiAI result has no complete sealed target plan'
            }
            $convertIdentities = {
                param([object[]]$Items)
                @($Items | ForEach-Object {
                        $path = [string]$_.Path
                        # User-scoped intent describes HKCU as a role, not the
                        # SID that happened to own Explorer during Apply. The
                        # verifier resolves that role to its current interactive
                        # user and never misreports a user switch as 43 failures.
                        if ($path -match '^HKU:\\S-1-(?:5-21|12-1)-[0-9-]+\\(.+)$') {
                            $path = 'HKCU:\' + $Matches[1]
                        }
                        [ordered]@{ path = $path; name = [string]$_.Name }
                    })
            }
            return [ordered]@{
                applicableTargets = @(& $convertIdentities $applicable)
                notApplicableTargets = @(& $convertIdentities $notApplicable)
            }
        }
        'EdgeHardening' { return [ordered]@{ allowExtensions = [bool]$ModuleResult.AllowExtensions } }
        'AdvancedSecurity' {
            if ([string]$ModuleResult.SecurityProfile -notin @('Balanced', 'Enterprise', 'Maximum')) {
                throw 'A successful AdvancedSecurity result has an invalid profile'
            }
            return [ordered]@{
                securityProfile = [string]$ModuleResult.SecurityProfile
                skipFirewallLayer = [bool]$ModuleResult.SkipFirewallLayer
                disableRDP = [bool]$ModuleResult.DisableRDP
                adminSharesDisabled = [bool]$ModuleResult.AdminSharesDisabled
                disableUPnP = [bool]$ModuleResult.DisableUPnP
                disableWirelessDisplay = [bool]$ModuleResult.DisableWirelessDisplayCompletely
                disableDiscoveryProtocols = [bool]$ModuleResult.DisableDiscoveryProtocolsCompletely
                disableIPv6 = [bool]$ModuleResult.DisableIPv6Completely
                enableFirewallShieldsUp = [bool]$ModuleResult.EnableFirewallShieldsUp
            }
        }
        default { throw "Cannot create Apply intent for unknown module: $moduleName" }
    }
}

function Write-NoIDApplyIntentState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$ModuleResults,
        [Parameter(Mandatory = $false)][string]$SessionPath
    )

    $eligibleResults = @($ModuleResults | Where-Object {
            if ($_ -isnot [PSCustomObject]) { return $false }
            if ([bool]$_.Success) { return $true }
            # Compatibility with a legacy pre-2.2.5 result shape. Current DNS KEEP is
            # a successful explicit no-mutation decision, but a schema-valid
            # older result must remain representable during an in-place run.
            return ([string]$_.ModuleName -ceq 'DNS' -and
                [string]$_.Status -ceq 'Skipped' -and
                [string]$_.Provider -ceq 'KEEP' -and
                [string]$_.DoHMode -ceq 'KEEP')
        })
    if ($eligibleResults.Count -eq 0) { return $null }

    $isDnsKeepResult = {
        param($Result)
        [string]$Result.ModuleName -ceq 'DNS' -and
            [string]$Result.Provider -ceq 'KEEP' -and
            [string]$Result.DoHMode -ceq 'KEEP'
    }
    $successfulResults = @($eligibleResults | Where-Object {
            [bool]$_.Success -and -not (& $isDnsKeepResult $_)
        })
    $manifest = $null
    $manifestHash = $null
    if ($successfulResults.Count -gt 0) {
        if ([string]::IsNullOrWhiteSpace($SessionPath)) {
            throw 'Successful Apply has no session path for intent binding'
        }
        $sessionRoot = [System.IO.Path]::GetFullPath($SessionPath).TrimEnd('\', '/')
        $manifestPath = Join-Path $sessionRoot 'manifest.json'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw 'Successful Apply has no sealed session manifest for intent binding'
        }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        Assert-SessionManifest -SessionPath $sessionRoot -Manifest $manifest
        $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    $engineFingerprint = Get-NoIDEngineContractFingerprint

    $moduleMap = [ordered]@{}
    $existing = $null
    try { $existing = Read-NoIDIntentState -AllowMissing }
    catch {
        Write-Log -Level WARNING -Message "Existing Apply-intent record is invalid and will not be reused: $($_.Exception.Message)" -Module 'IntentState'
    }
    # A reviewed engine update does not erase a still-valid user decision.
    # Schema validation above is the compatibility contract; individual
    # consumers additionally bind inventory-shaped choices (for example ASR)
    # to their current declared targets. The old engine hash remains recorded
    # in each source's history/provenance, but is not a substitute for schema.
    if ($existing) {
        foreach ($property in @($existing.modules.PSObject.Properties)) {
            # Schema 2 intentionally had no AntiAI plan. Carrying that empty
            # placeholder into schema 3 would falsely label a live-derived
            # scope as sealed intent, so drop it until AntiAI is applied again.
            if ([int]$existing.schemaVersion -eq 2 -and [string]$property.Name -ceq 'AntiAI') {
                continue
            }
            $moduleMap[[string]$property.Name] = $property.Value
        }
    }

    foreach ($moduleResult in $eligibleResults) {
        $moduleName = [string]$moduleResult.ModuleName
        if ($moduleName -cnotin $script:NoIDIntentModuleNames) {
            throw "Successful result has unknown module identity: $moduleName"
        }
        $isKeepDecision = & $isDnsKeepResult $moduleResult
        $sourceEvidence = if ($isKeepDecision) {
            $bytes = [Text.Encoding]::UTF8.GetBytes('DNS|KEEP|KEEP')
            $sha = [Security.Cryptography.SHA256]::Create()
            try { ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
            finally { $sha.Dispose() }
        }
        else { $manifestHash }
        $moduleMap[$moduleName] = [ordered]@{
            moduleName = $moduleName
            recordedAt = (Get-Date).ToUniversalTime().ToString('o')
            sourceKind = $(if ($isKeepDecision) { 'ApplyDecision' } else { 'ApplySession' })
            sourceId = $(if ($isKeepDecision) { 'DNS-KEEP' } else { [string]$manifest.sessionId })
            sourceEvidenceSha256 = $sourceEvidence
            intent = New-NoIDModuleIntent -ModuleResult $moduleResult
        }
    }

    $state = [ordered]@{
        schemaVersion = $script:NoIDIntentStateSchema
        frameworkVersion = Get-FrameworkVersion
        engineContractFingerprint = $engineFingerprint
        updatedAt = (Get-Date).ToUniversalTime().ToString('o')
        modules = $moduleMap
    }
    $statePath = Publish-NoIDIntentState -State $state
    $persisted = Read-NoIDIntentState
    if ([string]$persisted.engineContractFingerprint -cne $engineFingerprint) {
        throw 'Apply-intent round-trip fingerprint mismatch'
    }
    return $statePath
}

function Remove-NoIDApplyIntentModules {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Internal restore bookkeeping; the already-confirmed restore owns ShouldProcess and this helper must never prompt.'
    )]
    param([Parameter(Mandatory)][string[]]$ModuleNames)

    try {
        $state = Read-NoIDIntentState -AllowMissing
    }
    catch {
        # Intent is only a comparison label, never restore authority. An
        # unreadable or untrusted record is already ignored by verification;
        # it must not turn an otherwise exact live-state restore into failure.
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level WARNING -Message "Invalid Apply-intent record was already non-authoritative and could not be pruned after Restore: $($_.Exception.Message)" -Module 'IntentState'
        }
        return $true
    }
    if (-not $state) { return $true }
    $unknown = @($ModuleNames | Where-Object { $_ -cnotin $script:NoIDIntentModuleNames })
    if ($unknown.Count -gt 0) { throw "Cannot invalidate unknown intent modules: $($unknown -join ', ')" }

    $remaining = [ordered]@{}
    foreach ($property in @($state.modules.PSObject.Properties)) {
        if ([string]$property.Name -cnotin $ModuleNames) {
            $remaining[[string]$property.Name] = $property.Value
        }
    }
    if ($remaining.Count -eq 0) {
        $statePath = Get-NoIDIntentStatePath
        $null = Assert-NoIDIntentStateAcl -StatePath $statePath
        Remove-Item -LiteralPath $statePath -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $statePath) {
            throw 'Apply-intent record still exists after invalidating its final module'
        }
        return $true
    }
    $updated = [ordered]@{
        schemaVersion = [int]$state.schemaVersion
        frameworkVersion = [string]$state.frameworkVersion
        engineContractFingerprint = [string]$state.engineContractFingerprint
        updatedAt = (Get-Date).ToUniversalTime().ToString('o')
        modules = $remaining
    }
    $null = Assert-NoIDIntentState -State ($updated | ConvertTo-Json -Depth 20 | ConvertFrom-Json -ErrorAction Stop)
    $null = Publish-NoIDIntentState -State $updated
    $null = Assert-NoIDIntentState -State (Read-NoIDIntentState)
    return $true
}

function Update-NoIDQuickActionIntentState {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Internal Quick Action bookkeeping; the confirmed operation owns ShouldProcess and this helper must never prompt.'
    )]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'ManagementTools', 'NewSoftware', 'EncryptedDNS', 'BitLockerUSB',
            'RDP', 'UPnP', 'WirelessDisplay', 'EdgeExtensions', 'SmartScreen'
        )]
        [string]$ActionId,

        [Parameter(Mandatory)]
        [ValidateSet('Allow', 'Block', 'Require', 'Enforce', 'Disable', 'Enable', 'Warn')]
        [string]$DesiredState,

        [Parameter(Mandatory)]
        [ValidateSet('QuickActionApply', 'QuickActionRestore', 'QuickActionLiveConfirmation')]
        [string]$SourceKind,

        [Parameter(Mandatory = $false)]
        [string]$SourceSessionPath,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$SourceEvidenceSha256,

        # Required only for an EncryptedDNS live-confirmation without a sealed
        # session document. Apply/Restore derive it from the sealed state.
        [Parameter(Mandatory = $false)]
        [string]$DnsProvider
    )

    $state = Read-NoIDIntentState -AllowMissing
    if (-not $state) { return $true }
    $sourceId = $null
    $sourceDocument = $null
    if ($SourceKind -in @('QuickActionApply', 'QuickActionRestore')) {
        if ([string]::IsNullOrWhiteSpace($SourceSessionPath)) {
            throw "$SourceKind requires a Quick Action session path"
        }
        $sourceDocument = Get-QuickActionSessionDocument -SessionPath $SourceSessionPath
        $sourceId = [string]$sourceDocument.Manifest.sessionId
        $SourceEvidenceSha256 = (Get-FileHash `
                -LiteralPath (Join-Path ([string]$sourceDocument.SessionPath) 'manifest.json') `
                -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    else {
        if ([string]::IsNullOrWhiteSpace($SourceEvidenceSha256)) {
            throw 'QuickActionLiveConfirmation requires the verified live fingerprint'
        }
        $sourceId = $ActionId
    }

    $touchedModules = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $getIntent = {
        param([string]$ModuleName)
        $property = $state.modules.PSObject.Properties[$ModuleName]
        if ($property) {
            return $property.Value.intent
        }
        return $null
    }
    $markTouched = {
        param([string]$ModuleName)
        $null = $touchedModules.Add($ModuleName)
    }
    switch ($ActionId) {
        { $_ -in @('ManagementTools', 'NewSoftware') } {
            $asr = & $getIntent 'ASR'
            if ($asr) {
                $definitionGuid = if ($ActionId -eq 'ManagementTools') {
                    'd1e49aac-8f56-4280-b9ba-993a6d77406c'
                } else { '01443614-cd74-433a-b99e-2ecdc07bfc25' }
                $action = if ($DesiredState -eq 'Block') { 1 } else { 2 }
                $matching = @($asr.requestedActions | Where-Object { [string]$_.Guid -ceq $definitionGuid })
                if ($matching.Count -ne 1) { throw "ASR intent does not contain Quick Action target $definitionGuid" }
                if ([int]$matching[0].Action -ne $action) {
                    $matching[0].Action = $action
                    & $markTouched 'ASR'
                }
            }
            # Only ManagementTools overlaps a registry target the SecurityBaseline
            # inventory actually declares: Computer-RegistryPolicies.json contains
            # d1e49aac-... exactly once and 01443614-... not at all. Writing an
            # override for the undeclared NewSoftware GUID published a durable
            # SecurityBaseline intent record that every later standalone run of
            # Verify-Complete-Hardening.ps1 rejects with "Durable SecurityBaseline
            # ASR override is invalid", so a single Quick Action permanently broke
            # verification of all declared baseline registry checks. NewSoftware's
            # own ASR intent is still reconciled above; only the baseline label,
            # which has nothing to compare against, is skipped.
            $baseline = & $getIntent 'SecurityBaseline'
            if ($baseline) {
                # Heal records the published 2.2.5 write path already poisoned:
                # the undeclared NewSoftware GUID can never be a legitimate
                # baseline override, so either Quick Action drops it the next
                # time it touches the intent. Verification stays read-only; the
                # repair rides an event that rewrites the record anyway.
                $legacyNewSoftwareGuid = '01443614-cd74-433a-b99e-2ecdc07bfc25'
                if (@($baseline.asrActionOverrides | Where-Object {
                            [string]$_.Guid -ceq $legacyNewSoftwareGuid
                        }).Count -gt 0) {
                    $baseline | Add-Member -NotePropertyName asrActionOverrides -NotePropertyValue @(
                        @($baseline.asrActionOverrides | Where-Object {
                                [string]$_.Guid -cne $legacyNewSoftwareGuid
                            })
                    ) -Force
                    & $markTouched 'SecurityBaseline'
                    Write-Log -Level WARNING -Message "Removed the undeclared legacy NewSoftware baseline override $legacyNewSoftwareGuid written by 2.2.5" -Module 'IntentState'
                }
            }
            if ($baseline -and $ActionId -eq 'ManagementTools') {
                $definitionGuid = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
                $existingMatching = @($baseline.asrActionOverrides | Where-Object {
                        [string]$_.Guid -ceq $definitionGuid
                    })
                $desiredAction = $(if ($DesiredState -eq 'Block') { 1 } else { 2 })
                $overrides = @($baseline.asrActionOverrides | Where-Object {
                        [string]$_.Guid -cne $definitionGuid
                    })
                $overrides += [PSCustomObject]@{
                    Guid = $definitionGuid
                    Action = $desiredAction
                }
                if ($existingMatching.Count -ne 1 -or
                    [int]$existingMatching[0].Action -ne $desiredAction) {
                    $baseline | Add-Member -NotePropertyName asrActionOverrides -NotePropertyValue @($overrides) -Force
                    & $markTouched 'SecurityBaseline'
                }
            }
        }
        'EncryptedDNS' {
            $intent = & $getIntent 'DNS'
            if ($intent) {
                $sourceState = if ($SourceKind -eq 'QuickActionRestore') {
                    $sourceDocument.PreState
                }
                elseif ($SourceKind -eq 'QuickActionApply') {
                    $sourceDocument.PostState
                }
                else { $null }
                $provider = if ($sourceState) {
                    [string]$sourceState.targets.resolverEvidence.providerId
                }
                else { [string]$DnsProvider }
                if ($provider -notin @('Quad9','Cloudflare','AdGuard')) {
                    throw 'Encrypted DNS intent reconciliation requires one exact supported live provider'
                }
                $mode = if ($DesiredState -eq 'Require') { 'REQUIRE' } else { 'ALLOW' }
                if ([string]$intent.provider -cne $provider -or
                    [string]$intent.dohMode -cne $mode) {
                    $intent.provider = $provider
                    $intent.dohMode = $mode
                    & $markTouched 'DNS'
                }
            }
        }
        'BitLockerUSB' {
            $intent = & $getIntent 'SecurityBaseline'
            $desired = ($DesiredState -eq 'Enforce')
            if ($intent -and [bool]$intent.bitLockerUSBEnforcement -ne $desired) {
                $intent.bitLockerUSBEnforcement = $desired
                & $markTouched 'SecurityBaseline'
            }
        }
        'RDP' {
            $intent = & $getIntent 'AdvancedSecurity'
            $desired = ($DesiredState -eq 'Disable')
            if ($intent -and [bool]$intent.disableRDP -ne $desired) {
                $intent.disableRDP = $desired
                & $markTouched 'AdvancedSecurity'
            }
        }
        'UPnP' {
            $intent = & $getIntent 'AdvancedSecurity'
            $desired = ($DesiredState -eq 'Block')
            if ($intent -and [bool]$intent.disableUPnP -ne $desired) {
                $intent.disableUPnP = $desired
                & $markTouched 'AdvancedSecurity'
            }
        }
        'WirelessDisplay' {
            $intent = & $getIntent 'AdvancedSecurity'
            $desired = ($DesiredState -eq 'Disable')
            if ($intent -and [bool]$intent.disableWirelessDisplay -ne $desired) {
                $intent.disableWirelessDisplay = $desired
                & $markTouched 'AdvancedSecurity'
            }
        }
        'EdgeExtensions' {
            $intent = & $getIntent 'EdgeHardening'
            $desired = ($DesiredState -eq 'Allow')
            if ($intent -and [bool]$intent.allowExtensions -ne $desired) {
                $intent.allowExtensions = $desired
                & $markTouched 'EdgeHardening'
            }
        }
        'SmartScreen' {
            $intent = & $getIntent 'SecurityBaseline'
            $desired = ($DesiredState -eq 'Warn')
            if ($intent -and [bool]$intent.smartScreenWarnMode -ne $desired) {
                $intent.smartScreenWarnMode = $desired
                & $markTouched 'SecurityBaseline'
            }
        }
    }

    $recordedAt = (Get-Date).ToUniversalTime().ToString('o')
    foreach ($moduleName in $touchedModules) {
        $record = $state.modules.PSObject.Properties[$moduleName].Value
        $record.recordedAt = $recordedAt
        $record.sourceKind = $SourceKind
        $record.sourceId = $sourceId
        $record.sourceEvidenceSha256 = $SourceEvidenceSha256
    }
    if ($touchedModules.Count -eq 0) { return $true }
    # engineContractFingerprint remains the provenance of the Apply document.
    # A Quick Action records exact per-module evidence below but must not imply
    # that every untouched module was applied by the current engine content.
    $state.updatedAt = $recordedAt
    $null = Assert-NoIDIntentState -State ($state | ConvertTo-Json -Depth 20 | ConvertFrom-Json -ErrorAction Stop)
    $null = Publish-NoIDIntentState -State $state
    $null = Assert-NoIDIntentState -State (Read-NoIDIntentState)
    return $true
}
