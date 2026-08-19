#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI', 'EdgeHardening', 'AdvancedSecurity')]
    [ValidateCount(1, 7)]
    # Run the restart- and remote-management-sensitive baseline last so its
    # successful restore cannot leave a pending policy cycle for later modules.
    [string[]]$Modules = @('ASR', 'DNS', 'Privacy', 'AntiAI', 'EdgeHardening', 'AdvancedSecurity', 'SecurityBaseline'),

    [Parameter(Mandatory = $true)]
    [switch]$ConfirmDisposableVm,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Windows11-BAVR-Results.json'),

    [Parameter(Mandatory = $false)]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $false)]
    [string]$ConfigurationPath
)

$ErrorActionPreference = 'Stop'
if (-not $ConfirmDisposableVm -or $env:NOID_DISPOSABLE_VM -ne 'true') {
    throw 'Refusing destructive BAVR validation without both -ConfirmDisposableVm and NOID_DISPOSABLE_VM=true'
}
if (@($Modules | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
    throw 'The BAVR module list contains a duplicate identity'
}
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$entryPoint = Join-Path $repoRoot 'NoIDPrivacy.ps1'
$configPath = if ([string]::IsNullOrWhiteSpace($ConfigurationPath)) {
    Join-Path $repoRoot 'config.json'
}
else {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigurationPath)
}
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "BAVR configuration file is missing: $configPath"
}
$configSha256 = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
$backupRoot = Join-Path $repoRoot 'Backups'
$stateRunner = Join-Path $repoRoot 'Tests\Windows11\Invoke-Windows11DecisionMatrix.ps1'
$stateFingerprintHelper = Join-Path $repoRoot 'Tests\Windows11\Windows11StateFingerprint.ps1'
$verifierPath = Join-Path $repoRoot 'Tools\Verify-Complete-Hardening.ps1'
if (-not (Test-Path -LiteralPath $stateFingerprintHelper -PathType Leaf)) {
    throw "Windows 11 state-fingerprint helper is missing: $stateFingerprintHelper"
}
if (-not (Test-Path -LiteralPath $verifierPath -PathType Leaf)) {
    throw "Complete-hardening verifier is missing: $verifierPath"
}
. $stateFingerprintHelper
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
    throw "Windows PowerShell 5.1 executable is missing: $windowsPowerShell"
}
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $outputParent = Split-Path -Parent $OutputPath
    if ([string]::IsNullOrWhiteSpace($outputParent)) { $outputParent = $PSScriptRoot }
    $EvidenceDirectory = Join-Path $outputParent 'Windows11-BAVR-State'
}
$null = New-Item -ItemType Directory -Path $EvidenceDirectory -Force -ErrorAction Stop

$script:RestoreReceiptFileName = 'restore-receipt.json'

function Get-SessionFileHashes {
    <#
    .SYNOPSIS
        Hash the sealed contents of a session, excluding the restore receipt.
    .DESCRIPTION
        This inventory proves that a restore leaves the sealed prestate exactly
        as it found it. The restore receipt is the one file a successful restore
        is meant to add or update - it is the audit record of that restore, not
        part of the sealed state - so comparing it here would make every restore
        look like session tampering. Assert-RestoreReceipt checks it positively
        instead, so excluding it here loses no coverage.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SessionPath)

    $hashes = @{}
    foreach ($file in Get-ChildItem -LiteralPath $SessionPath -File -Recurse -Force -ErrorAction Stop) {
        $relativePath = $file.FullName.Substring($SessionPath.Length).TrimStart('\')
        if ($relativePath -ieq $script:RestoreReceiptFileName) { continue }
        $hashes[$relativePath] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    return $hashes
}

function Assert-RestoreReceipt {
    <#
    .SYNOPSIS
        Prove the restore wrote its own audit record for this exact session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SessionPath,
        [Parameter(Mandatory = $true)][string]$Module
    )

    $receiptPath = Join-Path $SessionPath $script:RestoreReceiptFileName
    if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
        throw "The $Module restore left no restore receipt in $SessionPath"
    }
    $receipt = Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $sessionLeaf = Split-Path -Path $SessionPath -Leaf
    if ([int]$receipt.schemaVersion -ne 1 -or
        [string]$receipt.recordType -cne 'NoIDRestoreReceipt' -or
        [string]$receipt.sessionId -cne $sessionLeaf) {
        throw "The $Module restore receipt does not identify session ${sessionLeaf} under schema 1"
    }
    if (@($receipt.restoredScopes) -cnotcontains "module:$Module") {
        throw "The $Module restore receipt does not record a module:$Module scope"
    }
    $completedAt = [datetime]::MinValue
    if (-not [datetime]::TryParse([string]$receipt.completedAt, [ref]$completedAt)) {
        throw "The $Module restore receipt has an invalid completedAt value"
    }
    return $receipt
}

function Invoke-AppliedScopeVerification {
    <#
    .SYNOPSIS
        Prove that CLI, exported JSON and HTML consume one reconciled result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$Sequence,
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$SessionPath,
        [Parameter(Mandatory = $true)][string]$EffectiveConfigurationPath
    )

    $exportPath = Join-Path $EvidenceDirectory ('{0:D2}-{1}-verify.json' -f $Sequence, $Module)
    Remove-Item -LiteralPath $exportPath -Force -ErrorAction SilentlyContinue
    $arguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $verifierPath,
        '-ExportPath', $exportPath,
        '-ModulesCsv', $Module,
        '-ConfigPath', $EffectiveConfigurationPath,
        '-AppliedSessionPath', $SessionPath,
        '-RedactComputerName'
    )
    $verificationOutput = @(& $windowsPowerShell @arguments 2>&1)
    $exitCode = [int]$LASTEXITCODE
    $contractLine = @($verificationOutput | ForEach-Object { [string]$_ } |
        Where-Object { $_.StartsWith('NOID_VERIFY_JSON=', [StringComparison]::Ordinal) } |
        Select-Object -Last 1)
    if ($exitCode -ne 0 -or $contractLine.Count -ne 1 -or
        -not (Test-Path -LiteralPath $exportPath -PathType Leaf)) {
        $diagnostic = @($verificationOutput | ForEach-Object { [string]$_ }) -join ' | '
        if ([string]::IsNullOrWhiteSpace($diagnostic)) { $diagnostic = '<no child-process output>' }
        throw "Applied-scope verification contract failed for ${Module}: exitCode=$exitCode; $diagnostic"
    }

    $contract = $contractLine[0].Substring('NOID_VERIFY_JSON='.Length) |
        ConvertFrom-Json -ErrorAction Stop
    $document = Get-Content -LiteralPath $exportPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $effectiveConfigurationSha256 = (Get-FileHash `
            -LiteralPath $EffectiveConfigurationPath `
            -Algorithm SHA256 `
            -ErrorAction Stop).Hash.ToLowerInvariant()
    $selectedModules = @($document.SelectedModules)
    $countsReconcile = ([int]$document.Verified + [int]$document.Failed +
        [int]$document.NotChecked + [int]$document.NotApplicable) -eq [int]$document.TotalSettings
    $notCheckedDispositionCountsReconcile =
        ([int]$document.NotCheckedDeliberate + [int]$document.NotCheckedNoSavedChoice +
        [int]$document.NotCheckedCannotVerify) -eq [int]$document.NotChecked
    $inventoryReconciles = [int]$document.ProductTargetInventory -ge [int]$document.TotalSettings
    $accepted = [int]$document.Failed -eq 0 -and
        [int]$document.NotChecked -eq [int]$document.NotCheckedDeliberate -and
        $countsReconcile -and $notCheckedDispositionCountsReconcile -and $inventoryReconciles
    if ([int]$contract.schemaVersion -ne 3 -or
        $selectedModules.Count -ne 1 -or [string]$selectedModules[0] -cne $Module -or
        -not [bool]$document.AppliedScopeRun -or -not $accepted -or
        [bool]$contract.complete -ne $accepted -or
        [int]$contract.total -ne [int]$document.TotalSettings -or
        [int]$contract.verified -ne [int]$document.Verified -or
        [int]$contract.failed -ne [int]$document.Failed -or
        [int]$contract.notChecked -ne [int]$document.NotChecked -or
        [int]$contract.notCheckedDeliberate -ne [int]$document.NotCheckedDeliberate -or
        [int]$contract.notApplicable -ne [int]$document.NotApplicable -or
        [string]$contract.intentReference -cne 'Exact transaction-bound Apply configuration' -or
        # Each BAVR cycle materializes a one-module configuration. The
        # verifier is bound to that exact payload, not to the wider source
        # configuration from which the cycle was derived.
        [string]$contract.configSha256 -cne $effectiveConfigurationSha256 -or
        -not [bool]$contract.reportGenerated) {
        throw "Applied-scope JSON/GUI result reconciliation failed for $Module"
    }

    $reportPath = [IO.Path]::GetFullPath([string]$contract.reportPath)
    $reportsRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'Reports'))
    if (-not $reportPath.StartsWith($reportsRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        throw "Applied-scope HTML report path is missing or outside the report root for ${Module}: $reportPath"
    }
    $html = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 -ErrorAction Stop
    $notCheckedLabel = if ([int]$document.NotChecked -eq 0) {
        'Settings Not Checked'
    }
    elseif ([int]$document.NotChecked -eq [int]$document.NotCheckedDeliberate) {
        'Excluded by Choice'
    }
    elseif ([int]$document.NotChecked -eq [int]$document.NotCheckedNoSavedChoice) {
        'No Saved Choice'
    }
    elseif ([int]$document.NotChecked -eq [int]$document.NotCheckedCannotVerify) {
        'Could Not Verify'
    }
    else { 'Settings Not Checked' }
    $expectedStats = @(
        [PSCustomObject]@{ Value = [int]$document.TotalSettings; Label = 'Verification Scope' }
        [PSCustomObject]@{ Value = [int]$document.Verified; Label = 'Settings Passed' }
        [PSCustomObject]@{ Value = [int]$document.Failed; Label = 'Settings Failed' }
        [PSCustomObject]@{ Value = [int]$document.NotChecked; Label = $notCheckedLabel }
        [PSCustomObject]@{ Value = [int]$document.NotApplicable; Label = 'Settings Not Applicable' }
    )
    foreach ($stat in $expectedStats) {
        $pattern = '<div class="stat-value(?: [^"]+)?">\s*' + [regex]::Escape([string]$stat.Value) +
            '\s*</div>\s*<div class="stat-label">' + [regex]::Escape([string]$stat.Label) + '</div>'
        if (-not [regex]::IsMatch($html, $pattern, [Text.RegularExpressions.RegexOptions]::Singleline)) {
            throw "Applied-scope HTML does not render the canonical $($stat.Label)=$($stat.Value) result for $Module"
        }
    }
    if ($html.IndexOf('product targets', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Applied-scope HTML exposes the internal product inventory beside Verification Scope for $Module"
    }

    return [PSCustomObject]@{
        ExportPath = $exportPath
        ExportSha256 = (Get-FileHash -LiteralPath $exportPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        ReportPath = $reportPath
        ReportSha256 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        Total = [int]$document.TotalSettings
        ProductTargetInventory = [int]$document.ProductTargetInventory
        Verified = [int]$document.Verified
        Failed = [int]$document.Failed
        NotChecked = [int]$document.NotChecked
        NotCheckedDeliberate = [int]$document.NotCheckedDeliberate
        NotApplicable = [int]$document.NotApplicable
        Complete = [bool]$contract.complete
        Accepted = $accepted
    }
}

function New-ModuleScopedConfiguration {
    <#
    .SYNOPSIS
        Materialize the exact effective Apply plan for one BAVR module cycle.
    .DESCRIPTION
        The release runner intentionally gives every module its own sealed
        session and exact restore.  A repository configuration can enable all
        seven modules, but a cycle invokes NoIDPrivacy.ps1 with one -Module.
        The verifier must consume the same effective selection rather than the
        wider repository plan, so this helper preserves every configured
        decision while changing only the seven enabled flags.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)][int]$Sequence,
        [Parameter(Mandatory = $true)][string]$Module
    )

    $document = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if (-not $document.PSObject.Properties['modules'] -or $null -eq $document.modules) {
        throw 'BAVR source configuration has no module plan'
    }
    foreach ($declaredModule in @(
            'SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI',
            'EdgeHardening', 'AdvancedSecurity'
        )) {
        $moduleConfig = $document.modules.$declaredModule
        if ($null -eq $moduleConfig -or
            -not ($moduleConfig.PSObject.Properties.Name -contains 'enabled') -or
            $moduleConfig.enabled -isnot [bool]) {
            throw "BAVR source configuration has no Boolean enabled decision for $declaredModule"
        }
        $moduleConfig.enabled = ($declaredModule -ceq $Module)
    }
    if (-not $document.PSObject.Properties['options'] -or $null -eq $document.options -or
        -not ($document.options.PSObject.Properties.Name -contains 'nonInteractive')) {
        throw 'BAVR source configuration has no nonInteractive decision'
    }
    $document.options.nonInteractive = $true

    $path = Join-Path $EvidenceDirectory ('{0:D2}-{1}-effective-config.json' -f $Sequence, $Module)
    if (-not $PSCmdlet.ShouldProcess($path, "Write the closed $Module BAVR effective configuration")) {
        throw "BAVR effective configuration write was declined for $Module"
    }
    [IO.File]::WriteAllText(
        $path,
        ($document | ConvertTo-Json -Depth 20),
        [Text.UTF8Encoding]::new($false)
    )
    $roundTrip = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $enabledModules = @($roundTrip.modules.PSObject.Properties | Where-Object {
            $_.Value.enabled -is [bool] -and [bool]$_.Value.enabled
        } | ForEach-Object Name)
    if ($enabledModules.Count -ne 1 -or [string]$enabledModules[0] -cne $Module -or
        $roundTrip.options.nonInteractive -isnot [bool] -or -not [bool]$roundTrip.options.nonInteractive) {
        throw "BAVR effective configuration did not round-trip as the closed $Module plan"
    }
    return [PSCustomObject]@{
        Path = $path
        Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
}

function Invoke-IndependentStateFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$Sequence,
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][ValidateSet('pre', 'post')][string]$Phase
    )

    $fileName = '{0:D2}-{1}-{2}.json' -f $Sequence, $Module, $Phase
    $path = Join-Path $EvidenceDirectory $fileName
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    $arguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $stateRunner,
        '-ConfirmDisposableVm',
        '-StateOnly',
        '-StabilityDelaySeconds', '5',
        '-OutputPath', $path
    )
    # Keep the child runner's success stream out of this function's return
    # value.  Its human-readable success message would otherwise turn the
    # evidence object below into a heterogeneous Object[] under callers that
    # enable StrictMode.
    $stateProcessOutput = @(& $windowsPowerShell @arguments 2>&1)
    $exitCode = [int]$LASTEXITCODE
    if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $diagnostic = @($stateProcessOutput | ForEach-Object { [string]$_ }) -join ' | '
        if ([string]::IsNullOrWhiteSpace($diagnostic)) { $diagnostic = '<no child-process output>' }
        throw "Independent $Phase-state capture failed for $Module with exit code ${exitCode}: $diagnostic"
    }
    $document = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $internallyStable = $null -ne $document.StateBefore -and
        $null -ne $document.StateAfter -and
        [string]$document.StateBefore.CombinedHash -ceq [string]$document.StateAfter.CombinedHash -and
        @($document.RegistryDifferences).Count -eq 0
    if (-not [bool]$document.Passed -or [string]$document.Mode -cne 'StateOnly' -or -not $internallyStable) {
        throw "Independent $phase-state evidence is invalid or unstable for ${Module}: $($document.Error)"
    }
    return [PSCustomObject]@{
        Path = $path
        Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        Document = $document
    }
}

function Get-RegistryEntryIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entry)

    return (([string]$Entry.Root).ToLowerInvariant() + '|' + [string]$Entry.Kind + '|' +
        ([string]$Entry.Path).ToLowerInvariant() + '|' + ([string]$Entry.Name).ToLowerInvariant())
}

function Test-IsAllowedOsVolatileRegistryEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entry)

    return Test-Windows11OsOwnedVolatileRegistryEntry -Entry $Entry
}

function Compare-IndependentStateFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Before,
        [Parameter(Mandatory = $true)]$After
    )

    $componentComparisons = @($Before.StateAfter.Components.PSObject.Properties.Name | ForEach-Object {
            $name = [string]$_
            [PSCustomObject]@{
                Name = $name
                Before = [string]$Before.StateAfter.Components.$name
                After = [string]$After.StateAfter.Components.$name
                Equal = [string]$Before.StateAfter.Components.$name -ceq [string]$After.StateAfter.Components.$name
            }
        })
    $beforeMap = @{}
    foreach ($entry in @($Before.RegistrySnapshotBefore)) {
        $beforeMap[(Get-RegistryEntryIdentity -Entry $entry)] = $entry
    }
    $afterMap = @{}
    foreach ($entry in @($After.RegistrySnapshotBefore)) {
        $afterMap[(Get-RegistryEntryIdentity -Entry $entry)] = $entry
    }
    $rawRegistryDifferences = @(@($beforeMap.Keys + $afterMap.Keys) | Sort-Object -Unique | ForEach-Object {
            $identity = [string]$_
            $beforeEntry = $beforeMap[$identity]
            $afterEntry = $afterMap[$identity]
            $beforeJson = if ($null -eq $beforeEntry) { '<missing>' } else { $beforeEntry | ConvertTo-Json -Compress }
            $afterJson = if ($null -eq $afterEntry) { '<missing>' } else { $afterEntry | ConvertTo-Json -Compress }
            if ($beforeJson -cne $afterJson) {
                $sample = if ($null -ne $afterEntry) { $afterEntry } else { $beforeEntry }
                [PSCustomObject]@{
                    Identity = $identity
                    Root = [string]$sample.Root
                    Path = [string]$sample.Path
                    Name = [string]$sample.Name
                    Before = if ($null -ne $beforeEntry) { [string]$beforeEntry.Data } else { $null }
                    After = if ($null -ne $afterEntry) { [string]$afterEntry.Data } else { $null }
                    AllowedOsVolatile = Test-IsAllowedOsVolatileRegistryEntry -Entry $sample
                }
            }
        })
    $unapprovedRawDifferences = @($rawRegistryDifferences | Where-Object { -not $_.AllowedOsVolatile })
    $combinedHashEqual = [string]$Before.StateAfter.CombinedHash -ceq [string]$After.StateAfter.CombinedHash
    return [PSCustomObject]@{
        Passed = $combinedHashEqual -and
            @($componentComparisons | Where-Object { -not $_.Equal }).Count -eq 0 -and
            $unapprovedRawDifferences.Count -eq 0
        CombinedHashBefore = [string]$Before.StateAfter.CombinedHash
        CombinedHashAfter = [string]$After.StateAfter.CombinedHash
        StableRegistryEntryCountBefore = [int]$Before.StateAfter.StableRegistryEntryCount
        StableRegistryEntryCountAfter = [int]$After.StateAfter.StableRegistryEntryCount
        ComponentComparisons = $componentComparisons
        RawRegistryDifferences = $rawRegistryDifferences
        UnapprovedRawRegistryDifferences = $unapprovedRawDifferences
    }
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$currentVersion = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
$displayVersion = [string]$currentVersion.GetValue('DisplayVersion', '')
$build = [int]$os.BuildNumber
if ([int]$os.ProductType -ne 1 -or $build -lt 22000) {
    throw "Windows 11 client is required; actual build=$build ProductType=$($os.ProductType)"
}
if ($computer.PartOfDomain) { throw 'The destructive BAVR runner must not be domain joined' }
$supportedProfile = $displayVersion -ceq '25H2' -and $build -in 26200..26299
if (-not $supportedProfile) {
    throw "The current full seven-module release gate requires Windows 11 25H2; the recognized 26H2 Experimental Preview path requires a separate runtime-validation gate and is not release-approved; DisplayVersion='$displayVersion', build=$build"
}
$sessionId = (Get-Process -Id $PID -ErrorAction Stop).SessionId
if (@(Get-Process -Name explorer -ErrorAction Stop | Where-Object SessionId -eq $sessionId).Count -lt 1) {
    throw 'The self-hosted runner must run interactively in the same Explorer session, not as a service in session 0'
}

$priorSessions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if (Test-Path -LiteralPath $backupRoot -PathType Container) {
    foreach ($folder in Get-ChildItem -LiteralPath $backupRoot -Directory -ErrorAction Stop) {
        $null = $priorSessions.Add($folder.FullName)
    }
}
$records = [System.Collections.Generic.List[object]]::new()
$env:NOIDPRIVACY_NONINTERACTIVE = 'true'
$failureMessage = $null
foreach ($module in $Modules) {
    $sequence = $records.Count + 1
    $started = Get-Date
    $applyExitCode = $null
    $restoreExitCode = $null
    $sessionName = $null
    $cleanupRestoreAttempted = $false
    $cleanupRestoreSucceeded = $null
    $preStateEvidence = $null
    $postStateEvidence = $null
    $stateComparison = $null
    $manifestHashBefore = $null
    $manifestHashAfter = $null
    $sealedArtifactCount = 0
    $sessionFileCount = 0
    $sessionFilesUnchanged = $false
    $restoreReceipt = $null
    $appliedVerification = $null
    $appliedVerificationError = $null
    $effectiveConfiguration = $null
    try {
        $effectiveConfiguration = New-ModuleScopedConfiguration -Sequence $sequence -Module $module
        $preStateEvidence = Invoke-IndependentStateFingerprint -Sequence $sequence -Module $module -Phase pre
        $applyArguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $entryPoint, '-Module', $module, '-ConfigPath', $effectiveConfiguration.Path)
        $applyInvocationError = $null
        try {
            & $windowsPowerShell @applyArguments
            $applyExitCode = [int]$LASTEXITCODE
        }
        catch {
            $applyInvocationError = $_.Exception.Message
        }
        $newSessions = @(Get-ChildItem -LiteralPath $backupRoot -Directory -ErrorAction Stop |
            Where-Object { -not $priorSessions.Contains($_.FullName) } | Sort-Object LastWriteTimeUtc)
        foreach ($newSession in $newSessions) { $null = $priorSessions.Add($newSession.FullName) }
        $sealedSessions = @()
        $sessionDiagnostics = @()
        foreach ($candidate in $newSessions) {
            $candidateManifestPath = Join-Path $candidate.FullName 'manifest.json'
            if (-not (Test-Path -LiteralPath $candidateManifestPath -PathType Leaf)) {
                $sessionDiagnostics += "$($candidate.Name):no-manifest"
                continue
            }
            try {
                $candidateManifest = Get-Content -LiteralPath $candidateManifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop
                $candidateModules = @($candidateManifest.modules)
                if ([int]$candidateManifest.schemaVersion -eq 2 -and
                    $candidateManifest.restorable -is [bool] -and [bool]$candidateManifest.restorable -and
                    $candidateModules.Count -eq 1 -and [string]$candidateModules[0].name -ceq $module) {
                    $sealedSessions += $candidate
                    $sessionDiagnostics += "$($candidate.Name):sealed-$module"
                }
                else {
                    $sessionDiagnostics += "$($candidate.Name):not-restorable-$module"
                }
            }
            catch {
                $sessionDiagnostics += "$($candidate.Name):invalid-manifest-$($_.Exception.Message)"
            }
        }
        if ($newSessions.Count -ne 1 -or $sealedSessions.Count -ne 1) {
            $applyDetail = if ($applyInvocationError) { $applyInvocationError } else { "exit code $applyExitCode" }
            $diagnosticText = if ($sessionDiagnostics.Count -gt 0) { $sessionDiagnostics -join '; ' } else { 'none' }
            throw "Apply/Verify ended with $applyDetail and produced $($newSessions.Count) new backup folders, of which $($sealedSessions.Count) are the required sealed $module session; folders=$diagnosticText"
        }
        $session = $sealedSessions[0]
        $sessionName = $session.Name

        $manifestPath = Join-Path $session.FullName 'manifest.json'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "New backup folder has no sealed manifest: $($session.FullName)"
        }
        $sessionManifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $sealedModules = @($sessionManifest.modules)
        if ([int]$sessionManifest.schemaVersion -ne 2 -or
            $sessionManifest.restorable -isnot [bool] -or -not [bool]$sessionManifest.restorable -or
            $sealedModules.Count -ne 1 -or [string]$sealedModules[0].name -cne $module) {
            throw "New backup folder is not one restorable sealed $module session: $($session.FullName)"
        }

        $artifactInventory = @($sealedModules[0].artifacts) + @($sessionManifest.sharedArtifacts)
        if ($artifactInventory.Count -lt 1 -or [int]$sessionManifest.totalItems -ne $artifactInventory.Count) {
            throw "Sealed $module session has an incomplete artifact inventory: totalItems=$($sessionManifest.totalItems), artifacts=$($artifactInventory.Count)"
        }
        $relativePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($artifact in $artifactInventory) {
            $relativePath = [string]$artifact.relativePath
            $expectedHash = [string]$artifact.sha256
            if ([string]::IsNullOrWhiteSpace($relativePath) -or
                [IO.Path]::IsPathRooted($relativePath) -or
                @($relativePath -split '[\\/]' | Where-Object { $_ -eq '..' }).Count -gt 0 -or
                -not $relativePaths.Add($relativePath) -or
                $expectedHash -notmatch '^[a-f0-9]{64}$') {
                throw "Sealed $module session contains an invalid artifact declaration: '$relativePath'"
            }
            $artifactPath = Join-Path $session.FullName $relativePath
            if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
                throw "Sealed $module session is partial: missing '$relativePath'"
            }
            $actualHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
            if ($actualHash -cne $expectedHash) {
                throw "Sealed $module session artifact hash mismatch: '$relativePath'"
            }
        }
        $sealedArtifactCount = $artifactInventory.Count
        $manifestHashBefore = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $sessionHashesBefore = Get-SessionFileHashes -SessionPath $session.FullName
        $sessionFileCount = $sessionHashesBefore.Count

        $applySucceeded = (-not $applyInvocationError -and $applyExitCode -in @(0, 10))
        if ($applySucceeded) {
            try {
                $appliedVerification = Invoke-AppliedScopeVerification `
                    -Sequence $sequence `
                    -Module $module `
                    -SessionPath $session.FullName `
                    -EffectiveConfigurationPath $effectiveConfiguration.Path
            }
            catch {
                $appliedVerificationError = $_.Exception.Message
            }
        }
        $cleanupRestoreAttempted = -not $applySucceeded -or $null -ne $appliedVerificationError
        $restoreArguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $entryPoint, '-RestoreSessionPath', $session.FullName, '-ConfigPath', $effectiveConfiguration.Path)
        & $windowsPowerShell @restoreArguments
        $restoreExitCode = [int]$LASTEXITCODE
        if ($cleanupRestoreAttempted) {
            $cleanupRestoreSucceeded = ($restoreExitCode -eq 0)
        }
        if ($restoreExitCode -ne 0) {
            throw "BAVR Restore/exact verification failed for $module with exit code $restoreExitCode"
        }

        if (-not (Test-Path -LiteralPath $session.FullName -PathType Container)) {
            throw "The retained $module backup session disappeared during restore"
        }
        $manifestHashAfter = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $sessionHashesAfter = Get-SessionFileHashes -SessionPath $session.FullName
        $sessionFilesUnchanged = $manifestHashAfter -ceq $manifestHashBefore -and
            $sessionHashesAfter.Count -eq $sessionHashesBefore.Count -and
            @($sessionHashesBefore.Keys | Where-Object {
                    -not $sessionHashesAfter.ContainsKey($_) -or
                    $sessionHashesAfter[$_] -cne $sessionHashesBefore[$_]
                }).Count -eq 0
        $restoreReceipt = Assert-RestoreReceipt -SessionPath $session.FullName -Module $module
        if (-not $sessionFilesUnchanged) {
            throw "The retained $module backup session changed during restore"
        }

        $postStateEvidence = Invoke-IndependentStateFingerprint -Sequence $sequence -Module $module -Phase post
        $stateComparison = Compare-IndependentStateFingerprint `
            -Before $preStateEvidence.Document `
            -After $postStateEvidence.Document
        if (-not [bool]$stateComparison.Passed) {
            $changedComponents = @($stateComparison.ComponentComparisons | Where-Object { -not $_.Equal } | ForEach-Object Name)
            throw "Independent pre/post state comparison failed for ${module}: components=$($changedComponents -join ', '), unapprovedRegistryDifferences=$(@($stateComparison.UnapprovedRawRegistryDifferences).Count)"
        }
        if ($null -ne $appliedVerificationError) {
            throw "Applied-scope Verify/JSON/HTML validation failed for ${module}: $appliedVerificationError; the sealed prestate cleanup restore succeeded"
        }
        if (-not $applySucceeded) {
            $applyDetail = if ($applyInvocationError) { $applyInvocationError } else { "exit code $applyExitCode" }
            $cleanupDetail = if ($cleanupRestoreSucceeded) {
                'the sealed prestate cleanup restore succeeded'
            }
            else {
                "the sealed prestate cleanup restore failed with exit code $restoreExitCode"
            }
            throw "BAVR Apply/Verify failed for $module ($applyDetail); $cleanupDetail"
        }
        $records.Add([PSCustomObject]@{
                Module = $module; Session = $sessionName
                ApplyExitCode = $applyExitCode; RestoreExitCode = $restoreExitCode
                CleanupRestoreAttempted = $cleanupRestoreAttempted
                CleanupRestoreSucceeded = $cleanupRestoreSucceeded
                SealedArtifactCount = $sealedArtifactCount
                SessionFileCount = $sessionFileCount
                SessionManifestSha256Before = $manifestHashBefore
                SessionManifestSha256After = $manifestHashAfter
                SessionFilesUnchanged = $sessionFilesUnchanged
                EffectiveConfigurationPath = $effectiveConfiguration.Path
                EffectiveConfigurationSha256 = $effectiveConfiguration.Sha256
                RestoreReceiptCompletedAt = [string]$restoreReceipt.completedAt
                RestoreReceiptScopes = @($restoreReceipt.restoredScopes)
                PreStateEvidence = $preStateEvidence.Path
                PreStateEvidenceSha256 = $preStateEvidence.Sha256
                PostStateEvidence = $postStateEvidence.Path
                PostStateEvidenceSha256 = $postStateEvidence.Sha256
                IndependentStateComparison = $stateComparison
                AppliedVerification = $appliedVerification
                StartedAt = $started.ToString('o'); FinishedAt = (Get-Date).ToString('o')
                Result = 'Passed'; Error = $null
            })
    }
    catch {
        $failureMessage = $_.Exception.Message
        $records.Add([PSCustomObject]@{
                Module = $module; Session = $sessionName
                ApplyExitCode = $applyExitCode; RestoreExitCode = $restoreExitCode
                CleanupRestoreAttempted = $cleanupRestoreAttempted
                CleanupRestoreSucceeded = $cleanupRestoreSucceeded
                SealedArtifactCount = $sealedArtifactCount
                SessionFileCount = $sessionFileCount
                SessionManifestSha256Before = $manifestHashBefore
                SessionManifestSha256After = $manifestHashAfter
                SessionFilesUnchanged = $sessionFilesUnchanged
                EffectiveConfigurationPath = if ($null -ne $effectiveConfiguration) { $effectiveConfiguration.Path } else { $null }
                EffectiveConfigurationSha256 = if ($null -ne $effectiveConfiguration) { $effectiveConfiguration.Sha256 } else { $null }
                RestoreReceiptCompletedAt = if ($null -ne $restoreReceipt) { [string]$restoreReceipt.completedAt } else { $null }
                RestoreReceiptScopes = if ($null -ne $restoreReceipt) { @($restoreReceipt.restoredScopes) } else { @() }
                PreStateEvidence = if ($null -ne $preStateEvidence) { $preStateEvidence.Path } else { $null }
                PreStateEvidenceSha256 = if ($null -ne $preStateEvidence) { $preStateEvidence.Sha256 } else { $null }
                PostStateEvidence = if ($null -ne $postStateEvidence) { $postStateEvidence.Path } else { $null }
                PostStateEvidenceSha256 = if ($null -ne $postStateEvidence) { $postStateEvidence.Sha256 } else { $null }
                IndependentStateComparison = $stateComparison
                AppliedVerification = $appliedVerification
                AppliedVerificationError = $appliedVerificationError
                StartedAt = $started.ToString('o'); FinishedAt = (Get-Date).ToString('o')
                Result = 'Failed'; Error = $failureMessage
            })
        break
    }
}

$result = [PSCustomObject]@{
    SchemaVersion = 3
    CapturedAt = (Get-Date).ToString('o')
    DisplayVersion = $displayVersion
    BuildNumber = $build
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    ConfigurationPath = $configPath
    ConfigurationSha256 = $configSha256
    EvidenceDirectory = $EvidenceDirectory
    Modules = @($records)
    Error = $failureMessage
    Passed = ($null -eq $failureMessage -and $records.Count -eq $Modules.Count -and
        @($records | Where-Object Result -ne 'Passed').Count -eq 0)
}
[System.IO.File]::WriteAllText(
    $OutputPath,
    ($result | ConvertTo-Json -Depth 10),
    [System.Text.UTF8Encoding]::new($false)
)
if (-not $result.Passed) {
    Write-Host "Windows 11 BAVR validation failed: $failureMessage" -ForegroundColor Red
    exit 1
}
