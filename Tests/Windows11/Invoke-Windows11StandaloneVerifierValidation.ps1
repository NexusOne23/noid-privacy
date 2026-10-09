#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmDisposableVm,

    [Parameter(Mandatory = $true)]
    [string]$ConfigurationPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Windows11-Standalone-Verifier-Results.json'),

    [Parameter(Mandatory = $false)]
    [string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
if (-not $ConfirmDisposableVm -or $env:NOID_DISPOSABLE_VM -ne 'true') {
    throw 'Refusing destructive standalone-verifier validation without both -ConfirmDisposableVm and NOID_DISPOSABLE_VM=true'
}

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$entryPoint = Join-Path $repoRoot 'NoIDPrivacy.ps1'
$verifierPath = Join-Path $repoRoot 'Tools\Verify-Complete-Hardening.ps1'
$stateRunner = Join-Path $repoRoot 'Tests\Windows11\Invoke-Windows11DecisionMatrix.ps1'
$stateHelper = Join-Path $repoRoot 'Tests\Windows11\Windows11StateFingerprint.ps1'
$configurationFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigurationPath)
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
foreach ($requiredPath in @(
        $entryPoint, $verifierPath, $stateRunner, $stateHelper,
        $configurationFullPath, $windowsPowerShell
    )) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required standalone-verifier validation input is missing: $requiredPath"
    }
}
. $stateHelper

# Resolve operator paths once. .NET file APIs and child processes use the
# process working directory, which Windows PowerShell does not move with Set-Location.
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $outputParent = Split-Path -Parent $OutputPath
    if ([string]::IsNullOrWhiteSpace($outputParent)) { $outputParent = $PSScriptRoot }
    $EvidenceDirectory = Join-Path $outputParent 'Windows11-Standalone-Verifier-State'
}
$EvidenceDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($EvidenceDirectory)
$null = New-Item -ItemType Directory -Path $EvidenceDirectory -Force -ErrorAction Stop

$declaredModules = @(
    'SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI',
    'EdgeHardening', 'AdvancedSecurity'
)
$configuration = Get-Content -LiteralPath $configurationFullPath -Raw -Encoding UTF8 -ErrorAction Stop |
    ConvertFrom-Json -ErrorAction Stop
foreach ($moduleName in $declaredModules) {
    $moduleConfig = $configuration.modules.$moduleName
    if (-not $moduleConfig -or $moduleConfig.enabled -isnot [bool] -or -not [bool]$moduleConfig.enabled) {
        throw "Standalone-verifier validation requires all seven modules enabled; invalid: $moduleName"
    }
}
if ($configuration.options.nonInteractive -isnot [bool] -or
    -not [bool]$configuration.options.nonInteractive) {
    throw 'Standalone-verifier validation requires options.nonInteractive=true'
}
if ([string]$configuration.modules.Privacy.mode -cne 'Strict') {
    throw 'Standalone-verifier validation requires Privacy.mode=Strict'
}

$counts = Get-Content -LiteralPath (Join-Path $repoRoot 'Config\SettingsCounts.json') -Raw -Encoding UTF8 -ErrorAction Stop |
    ConvertFrom-Json -ErrorAction Stop
$expectedPrivacyCount = [int]$counts.modules.Privacy.modeTotals.Strict
$privacyModeCounts = @(
    [int]$counts.modules.Privacy.modeTotals.MSRecommended
    [int]$counts.modules.Privacy.modeTotals.Strict
    [int]$counts.modules.Privacy.modeTotals.Paranoid
)
$expectedPrivacyProductCount = [int](($privacyModeCounts | Measure-Object -Maximum).Maximum)
# The verification scope always contains the complete Privacy inventory; the
# Strict profile selects $expectedPrivacyCount of those targets.
$expectedTotal = [int]$counts.modules.SecurityBaseline.subtotal +
    [int]$counts.modules.ASR.rules + [int]$counts.modules.DNS.checks +
    $expectedPrivacyProductCount + [int]$counts.modules.AntiAI.total +
    [int]$counts.modules.EdgeHardening.policies +
    [int]$counts.modules.AdvancedSecurity.settings
$expectedProductInventory = $expectedTotal
if ($expectedPrivacyCount -ne 90) {
    throw "Canonical Strict Privacy total drifted from 90 to $expectedPrivacyCount; review this behavior contract"
}

function Invoke-StateCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('pre', 'post')][string]$Phase)

    $path = Join-Path $EvidenceDirectory "state-$Phase.json"
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    $output = @(& $windowsPowerShell @(
            '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', $stateRunner, '-ConfirmDisposableVm', '-StateOnly',
            '-StabilityDelaySeconds', '5', '-OutputPath', $path
        ) 2>&1)
    if ([int]$LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Independent $Phase state capture failed: $($output -join ' | ')"
    }
    $document = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if (-not [bool]$document.Passed -or
        [string]$document.StateBefore.CombinedHash -cne [string]$document.StateAfter.CombinedHash) {
        throw "Independent $Phase state capture was unstable"
    }
    return [PSCustomObject]@{ Path = $path; Document = $document }
}

function Get-RegistryEntryIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entry)

    return (([string]$Entry.Root).ToLowerInvariant() + '|' + [string]$Entry.Kind + '|' +
        ([string]$Entry.Path).ToLowerInvariant() + '|' + ([string]$Entry.Name).ToLowerInvariant())
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
    $rawDifferences = @(@($beforeMap.Keys + $afterMap.Keys) | Sort-Object -Unique | ForEach-Object {
            $identity = [string]$_
            $beforeEntry = $beforeMap[$identity]
            $afterEntry = $afterMap[$identity]
            $beforeJson = if ($null -eq $beforeEntry) { '<missing>' } else { $beforeEntry | ConvertTo-Json -Compress }
            $afterJson = if ($null -eq $afterEntry) { '<missing>' } else { $afterEntry | ConvertTo-Json -Compress }
            if ($beforeJson -cne $afterJson) {
                $sample = if ($null -ne $afterEntry) { $afterEntry } else { $beforeEntry }
                [PSCustomObject]@{
                    Identity = $identity
                    AllowedOsVolatile = Test-Windows11OsOwnedVolatileRegistryEntry -Entry $sample
                }
            }
        })
    $unapprovedDifferences = @($rawDifferences | Where-Object { -not $_.AllowedOsVolatile })
    return [PSCustomObject]@{
        Passed = [string]$Before.StateAfter.CombinedHash -ceq [string]$After.StateAfter.CombinedHash -and
            @($componentComparisons | Where-Object { -not $_.Equal }).Count -eq 0 -and
            $unapprovedDifferences.Count -eq 0
        ComponentComparisons = $componentComparisons
        UnapprovedRawRegistryDifferences = $unapprovedDifferences
    }
}

function Invoke-StandaloneVerification {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)

    $exportPath = Join-Path $EvidenceDirectory "$Name.json"
    Remove-Item -LiteralPath $exportPath -Force -ErrorAction SilentlyContinue
    $savedConfigPayload = $env:NOIDPRIVACY_CONFIG_JSON_BASE64
    try {
        $env:NOIDPRIVACY_CONFIG_JSON_BASE64 = $null
        $output = @(& $windowsPowerShell @(
                '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', $verifierPath, '-ExportPath', $exportPath,
                '-RedactComputerName'
            ) 2>&1)
        $exitCode = [int]$LASTEXITCODE
    }
    finally {
        $env:NOIDPRIVACY_CONFIG_JSON_BASE64 = $savedConfigPayload
    }
    $contractLines = @($output | ForEach-Object { [string]$_ } | Where-Object {
            $_.StartsWith('NOID_VERIFY_JSON=', [StringComparison]::Ordinal)
        })
    if ($exitCode -ne 0 -or $contractLines.Count -ne 1 -or
        -not (Test-Path -LiteralPath $exportPath -PathType Leaf)) {
        throw "Standalone verifier '$Name' did not emit one result contract: exit=$exitCode; $($output -join ' | ')"
    }
    $contract = $contractLines[0].Substring('NOID_VERIFY_JSON='.Length) |
        ConvertFrom-Json -ErrorAction Stop
    $document = Get-Content -LiteralPath $exportPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $notCheckedDispositionCountsReconcile =
        ([int]$document.NotCheckedDeliberate + [int]$document.NotCheckedNoSavedChoice +
        [int]$document.NotCheckedCannotVerify) -eq [int]$document.NotChecked
    if ([int]$contract.schemaVersion -ne 3 -or [bool]$document.AppliedScopeRun -or
        -not $notCheckedDispositionCountsReconcile -or
        [int]$contract.total -ne [int]$document.TotalSettings -or
        [int]$contract.failed -ne [int]$document.Failed -or
        [int]$contract.notChecked -ne [int]$document.NotChecked -or
        [int]$contract.notApplicable -ne [int]$document.NotApplicable -or
        [string]$contract.configSha256 -cne '') {
        throw "Standalone verifier '$Name' JSON and GUI contracts do not reconcile"
    }
    return [PSCustomObject]@{
        ExportPath = $exportPath
        Contract = $contract
        Document = $document
        Output = @($output | ForEach-Object { [string]$_ })
    }
}

function Get-StableVerificationJson {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Document)

    $clone = ($Document | ConvertTo-Json -Depth 20) | ConvertFrom-Json -ErrorAction Stop
    $clone.Duration = $null
    return ($clone | ConvertTo-Json -Compress -Depth 20)
}

function Assert-SelectedPrivacyVerifierUx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Verification,
        [Parameter(Mandatory = $true)][ValidateSet('MSRecommended','Strict','Paranoid')][string]$Mode,
        [Parameter(Mandatory = $true)][int]$Total
    )

    $privacyCategories = @($Verification.Document.AllSettings | Where-Object {
            [string]$_.Category -ceq 'Privacy'
        })
    if ($privacyCategories.Count -ne 1 -or
        -not $privacyCategories[0].PSObject.Properties['NotCheckedDeliberate']) {
        throw 'Standalone Privacy document does not contain one complete Privacy category result'
    }
    $privacyCategory = $privacyCategories[0]
    $passed = [int]$privacyCategory.Passed
    $failed = [int]$privacyCategory.Failed
    $notChecked = [int]$privacyCategory.NotChecked
    $intentional = [int]$privacyCategory.NotCheckedDeliberate
    $noSavedChoice = [int]$privacyCategory.NotCheckedNoSavedChoice
    $cannotVerify = [int]$privacyCategory.NotCheckedCannotVerify
    $unproven = $notChecked - $intentional
    $notApplicable = [int]$privacyCategory.NotApplicable
    if ([int]$privacyCategory.Total -ne $Total -or $failed -ne 0 -or $unproven -ne 0 -or
        ($intentional + $noSavedChoice + $cannotVerify) -ne $notChecked -or
        ($passed + $failed + $notChecked + $notApplicable) -ne $Total) {
        throw "Standalone Privacy category does not reconcile to a proven $Mode result on this Windows edition"
    }

    $expectedStatusLine = "  Privacy: [PASSED] $Mode"
    $expectedCountLine = "  $passed passed; 0 failed; $intentional by choice; $notApplicable not applicable ($Total targets)"
    if (@($Verification.Output | Where-Object { [string]$_ -ceq $expectedStatusLine }).Count -ne 1 -or
        @($Verification.Output | Where-Object { [string]$_ -ceq $expectedCountLine }).Count -ne 1) {
        throw "Standalone Privacy console UX did not publish one clear selected-profile verdict for $Mode"
    }
    foreach ($moduleStatusLine in @(
            '  Registry: [PASSED]',
            '  Audit Policies: [PASSED]',
            '  Security Template: [PASSED]',
            '  ASR Rules: [PASSED]',
            '  DNS: [PASSED]',
            '  AntiAI: [PASSED]',
            '  EdgeHardening: [PASSED]',
            '  AdvancedSecurity: [PASSED]'
        )) {
        if (@($Verification.Output | Where-Object {
                    [string]$_ -ceq $moduleStatusLine
                }).Count -ne 1) {
            throw "Standalone console UX did not publish one clear module result: $moduleStatusLine"
        }
    }
    $unselectedModeNames = @(@('MSRecommended','Strict','Paranoid') |
        Where-Object { $_ -cne $Mode } | ForEach-Object { [regex]::Escape($_) })
    $unselectedModePattern = '^\s+(?:' + ($unselectedModeNames -join '|') + '):'
    if (@($Verification.Output | Where-Object {
                [string]$_ -match $unselectedModePattern
            }).Count -ne 0) {
        throw 'Standalone Privacy console UX exposed unselected profile comparisons beside a valid selected-profile verdict'
    }

    $reportPath = [string]$Verification.Contract.reportPath
    if (-not [bool]$Verification.Contract.reportGenerated -or
        [string]::IsNullOrWhiteSpace($reportPath) -or
        -not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        throw 'Standalone verifier did not produce the HTML report required for Privacy UX validation'
    }
    $html = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 -ErrorAction Stop
    foreach ($requiredFragment in @(
            "(Privacy mode: $Mode)",
            '<div class="module-section" id="module-Privacy">',
            "<strong>$passed</strong>",
            "onclick=`"toggleModule('module-Privacy')`"",
            '<table class="settings-table">',
            '<th>Setting</th>',
            '<th>Path/Policy</th>',
            '<th>Expected</th>',
            '<th>Actual</th>',
            '<th>Status</th>'
        )) {
        if ($html.IndexOf($requiredFragment, [StringComparison]::Ordinal) -lt 0) {
            throw "Standalone HTML Privacy UX is missing required fragment: $requiredFragment"
        }
    }
    foreach ($forbiddenFragment in @(
            'Apply intent reference',
            'Durable Apply intent recorded',
            'First mismatches',
            '<span class="badge ',
            '<p class="verdict-detail">',
            '<section class="privacy-verdict',
            '<details class="profile-comparison">'
        )) {
        if ($html.IndexOf($forbiddenFragment, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "Standalone HTML Privacy UX exposed forbidden user-facing text: $forbiddenFragment"
        }
    }
    if ([regex]::Matches($html, [regex]::Escape($Mode)).Count -ne 1) {
        throw "Standalone HTML must name $Mode exactly once, in Verification Scope"
    }
}

function Get-StandaloneSessionSignature {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SessionPath)

    $root = Get-Item -LiteralPath $SessionPath -Force -ErrorAction Stop
    if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Recovery session must be an ordinary directory'
    }
    $items = [Collections.Generic.List[object]]::new()
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root.FullName)
    while ($pending.Count) {
        foreach ($item in @(Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction Stop)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Recovery session must not contain reparse points'
            }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
            else { $items.Add($item) }
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $root.FullName 'manifest.json') -PathType Leaf -ErrorAction Stop)) {
        throw 'Recovery session manifest is missing'
    }
    $files = [ordered]@{}
    foreach ($file in @($items | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($root.FullName.Length).TrimStart('\', '/')
        $files[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    return ($files | ConvertTo-Json -Compress)
}

function Copy-StandaloneRecoverySession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SessionPath,
        [Parameter(Mandatory = $true)][string]$ArchiveRoot
    )

    $source = Get-Item -LiteralPath $SessionPath -ErrorAction Stop
    $destination = Join-Path $ArchiveRoot $source.Name
    if (Test-Path -LiteralPath $destination -ErrorAction Stop) {
        throw "Archived session destination already exists: $destination"
    }
    $before = Get-StandaloneSessionSignature -SessionPath $source.FullName
    Copy-Item -LiteralPath $source.FullName -Destination $destination -Recurse -Force -ErrorAction Stop
    if ($before -cne (Get-StandaloneSessionSignature -SessionPath $source.FullName) -or
        $before -cne (Get-StandaloneSessionSignature -SessionPath $destination)) {
        throw 'Archived recovery session does not match every original session file'
    }
    return $destination
}

function Invoke-StandaloneRestore {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SessionPath)

    $output = @(& $windowsPowerShell @(
            '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', $entryPoint, '-RestoreSessionPath', $SessionPath,
            '-ConfigPath', $configurationFullPath
        ) 2>&1)
    return [PSCustomObject]@{ ExitCode = [int]$LASTEXITCODE; Output = @($output | ForEach-Object { [string]$_ }) }
}

function Invoke-StandaloneFailureRecovery {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$RecoverySession,
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$KnownSessions,
        [Parameter(Mandatory = $true)]$BeforeState
    )

    $recovery = [PSCustomObject]@{ Attempted=$false; Succeeded=$false; RestoreExitCode=$null; Error=$null }
    try {
        if ([string]::IsNullOrWhiteSpace($RecoverySession)) {
            $candidates = @(Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction Stop |
                Where-Object { -not $KnownSessions.Contains($_.FullName) })
            if ($candidates.Count -ne 1) {
                throw "Cannot select one recovery session: $($candidates.Count) new folders"
            }
            $RecoverySession = $candidates[0].FullName
        }
        $recovery.Attempted = $true
        $restore = Invoke-StandaloneRestore -SessionPath $RecoverySession
        $recovery.RestoreExitCode = $restore.ExitCode
        if ($restore.ExitCode -ne 0) { throw "Cleanup Restore failed with exit code $($restore.ExitCode)" }
        $after = Invoke-StateCapture -Phase post
        $comparison = Compare-IndependentStateFingerprint -Before $BeforeState -After $after.Document
        if (-not [bool]$comparison.Passed) { throw 'Cleanup Restore did not recover the independent pre-Apply state' }
        $recovery.Succeeded = $true
    }
    catch { $recovery.Error = $_.Exception.Message }
    return $recovery
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$currentVersion = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
$displayVersion = [string]$currentVersion.GetValue('DisplayVersion', '')
$build = [int]$os.BuildNumber
$supported24H2Profile = $displayVersion -ceq '24H2' -and $build -in 26100..26199
$supported25H2Profile = $displayVersion -ceq '25H2' -and $build -in 26200..26299
$supported26H2Profile = $displayVersion -ceq '26H2' -and $build -in 26300..27999
if ([int]$os.ProductType -ne 1 -or
    (-not $supported24H2Profile -and -not $supported25H2Profile -and -not $supported26H2Profile)) {
    throw "Windows 11 24H2/26100..26199, 25H2/26200..26299 or explicit 26H2/26300..27999 client is required; actual $displayVersion/$build"
}

$backupRoot = Join-Path $repoRoot 'Backups'
$knownSessions = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if (Test-Path -LiteralPath $backupRoot -PathType Container) {
    foreach ($folder in @(Get-ChildItem -LiteralPath $backupRoot -Directory -ErrorAction Stop)) {
        $null = $knownSessions.Add($folder.FullName)
    }
}

$preState = Invoke-StateCapture -Phase pre
$recoverySession = $null
$restoreCompleted = $false
try {
    $applyOutput = @(& $windowsPowerShell @(
            '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', $entryPoint, '-Module', 'All',
            '-ConfigPath', $configurationFullPath
        ) 2>&1)
    $applyExitCode = [int]$LASTEXITCODE
    $applyContractLine = @($applyOutput | ForEach-Object { [string]$_ } | Where-Object {
            $_.StartsWith('NOID_RESULT_JSON=', [StringComparison]::Ordinal)
        } | Select-Object -Last 1)
    if ($applyExitCode -notin @(0, 10) -or $applyContractLine.Count -ne 1) {
        throw "Full Strict Apply failed: exit=$applyExitCode; $($applyOutput -join ' | ')"
    }
    $applyContract = $applyContractLine[0].Substring('NOID_RESULT_JSON='.Length) |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$applyContract.schemaVersion -ne 2 -or -not [bool]$applyContract.success -or
        [int]$applyContract.modulesExecuted -ne 7 -or [int]$applyContract.modulesFailed -ne 0) {
        throw 'Full Strict Apply result contract did not report seven successful modules'
    }

    $newSessions = @(Get-ChildItem -LiteralPath $backupRoot -Directory -ErrorAction Stop |
        Where-Object { -not $knownSessions.Contains($_.FullName) })
    if ($newSessions.Count -ne 1) {
        throw "Full Strict Apply produced $($newSessions.Count) new sessions instead of exactly one"
    }
    $session = $newSessions[0]
    $recoverySession = $session.FullName
    $archiveRoot = Join-Path $EvidenceDirectory 'ArchivedSessions'
    $null = New-Item -ItemType Directory -Path $archiveRoot -Force -ErrorAction Stop
    $archivedSession = Copy-StandaloneRecoverySession -SessionPath $session.FullName -ArchiveRoot $archiveRoot
    $recoverySession = $archivedSession

    $beforeDeletion = Invoke-StandaloneVerification -Name 'standalone-before-session-delete'
    if ([int]$beforeDeletion.Document.TotalSettings -ne $expectedTotal -or
        [int]$beforeDeletion.Document.ProductTargetInventory -ne $expectedProductInventory -or
        [int]$beforeDeletion.Document.PrivacyChecks -ne $expectedPrivacyProductCount -or
        [string]$beforeDeletion.Document.PrivacyMode -cne 'Strict' -or
        [int]$beforeDeletion.Document.Failed -ne 0 -or
        [int]$beforeDeletion.Document.NotChecked -ne [int]$beforeDeletion.Document.NotCheckedDeliberate) {
        throw 'Strict standalone verification did not reconcile the canonical 90-target Privacy plan within the complete Privacy scope without uncertain failures'
    }
    Assert-SelectedPrivacyVerifierUx -Verification $beforeDeletion -Mode Strict -Total $expectedPrivacyProductCount

    Remove-Item -LiteralPath $session.FullName -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $session.FullName) {
        throw 'The original Apply session still exists after the backup-independence deletion step'
    }
    $afterDeletion = Invoke-StandaloneVerification -Name 'standalone-after-session-delete'
    Assert-SelectedPrivacyVerifierUx -Verification $afterDeletion -Mode Strict -Total $expectedPrivacyProductCount
    $beforeSignature = Get-StableVerificationJson -Document $beforeDeletion.Document
    $afterSignature = Get-StableVerificationJson -Document $afterDeletion.Document
    if ($beforeSignature -cne $afterSignature) {
        throw 'Standalone verifier result changed after deleting the latest backup session'
    }

    $driftPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
    $driftName = 'DisabledByGroupPolicy'
    $driftKey = Get-Item -LiteralPath $driftPath -ErrorAction Stop
    $driftKind = $driftKey.GetValueKind($driftName).ToString()
    $driftOriginal = $driftKey.GetValue($driftName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($driftKind -cne 'DWord' -or [int]$driftOriginal -ne 1) {
        throw "Strict Apply did not establish the named drift target as DWord/1: $driftPath\$driftName"
    }
    Set-ItemProperty -LiteralPath $driftPath -Name $driftName -Type DWord -Value 0 -ErrorAction Stop
    $drifted = Invoke-StandaloneVerification -Name 'standalone-named-drift'
    $namedFailures = @($drifted.Document.FailedSettings | ForEach-Object { @($_.Details) } | Where-Object {
            [string]$_.Path -like "*$driftName"
        })
    if ([int]$drifted.Document.Failed -lt 1 -or $namedFailures.Count -ne 1) {
        throw "Standalone verifier did not report exactly one named $driftName deviation"
    }

    $restore = Invoke-StandaloneRestore -SessionPath $archivedSession
    $restoreExitCode = $restore.ExitCode
    if ($restoreExitCode -ne 0) {
        throw "Archived exact Restore failed: exit=$restoreExitCode; $($restore.Output -join ' | ')"
    }
    $postState = Invoke-StateCapture -Phase post
    $comparison = Compare-IndependentStateFingerprint -Before $preState.Document -After $postState.Document
    if (-not [bool]$comparison.Passed) {
        throw 'Independent state fingerprint did not return to the exact pre-Apply state after Restore'
    }
    $restoreCompleted = $true
    $afterRestore = Invoke-StandaloneVerification -Name 'standalone-after-restore'
    if ([bool]$afterRestore.Contract.complete -or
        [string]$afterRestore.Contract.intentReference -notlike 'No durable Apply intent found*') {
        throw 'Post-Restore standalone verification retained a stale Apply claim or reported a false green result'
    }

    $result = [PSCustomObject]@{
        SchemaVersion = 1
        CapturedAt = (Get-Date).ToString('o')
        DisplayVersion = $displayVersion
        BuildNumber = [int]$os.BuildNumber
        ConfigurationPath = $configurationFullPath
        SessionRemovedFromBackupRoot = -not (Test-Path -LiteralPath $session.FullName)
        ArchivedSessionPath = $archivedSession
        PrivacyVerificationScope = [int]$beforeDeletion.Document.PrivacyChecks
        StandaloneTotal = [int]$beforeDeletion.Document.TotalSettings
        BackupIndependentResult = $beforeSignature -ceq $afterSignature
        NamedDriftTarget = "$driftPath\$driftName"
        NamedDriftFailures = $namedFailures.Count
        RestoreExitCode = $restoreExitCode
        ExactPrestateRestored = [bool]$comparison.Passed
        PostRestoreIntentReference = [string]$afterRestore.Contract.intentReference
        Passed = $true
    }
    [IO.File]::WriteAllText(
        $OutputPath,
        ($result | ConvertTo-Json -Depth 10),
        [Text.UTF8Encoding]::new($false)
    )
    Write-Host "Standalone verifier validation passed: $OutputPath" -ForegroundColor Green
}
finally {
    if (-not $restoreCompleted) {
        $recovery = Invoke-StandaloneFailureRecovery -RecoverySession $recoverySession `
            -BackupRoot $backupRoot -KnownSessions $knownSessions -BeforeState $preState.Document
        $recovery | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'failure-recovery.json') -Encoding UTF8 -ErrorAction Stop
        if (-not $recovery.Succeeded) {
            Write-Error "Standalone validation cleanup could not prove recovery: $($recovery.Error)" -ErrorAction Continue
        }
    }
}
