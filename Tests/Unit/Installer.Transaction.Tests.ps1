#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $tokens = $null
    $parseErrors = $null
    $installerAst = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repoRoot 'install.ps1'), [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -ne 0) { throw 'Installer must parse before testing its transaction' }

    # Execute the actual transaction in a child script: its exit statements must
    # return to Pester, and no prerequisite checks or network requests may run.
    $transactions = @($installerAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.TryStatementAst] -and
        $node.Body.Extent.Text -match 'Invoke-WebRequest -Uri \$downloadUrl -OutFile \$downloadPath'
    }, $true))
    if ($transactions.Count -ne 1) { throw 'Expected exactly one installer download/publication transaction' }

    $fixtureSetup = @'
param([string]$Root, [string]$Scenario)
$ErrorActionPreference = 'Stop'
$fullInstallPath = Join-Path $Root 'installation'
$stagingPath = Join-Path $Root 'staging'
$previousPath = Join-Path $Root 'previous'
$downloadPath = Join-Path $Root 'download.zip'
$downloadUrl = 'https://example.invalid/release.zip'
$checksumUrl = 'https://example.invalid/CHECKSUMS.sha256'
$zipAssetName = 'release.zip'
$expectedVersion = '9.9.9'
$retainedRuntimeDirectories = @('Backups', 'Logs', 'Reports')
$movedRuntimeDirectories = [System.Collections.Generic.List[string]]::new()
$previousMoved = $false
$newInstallMoved = $false
$stagingCreated = $false
$downloadCreated = $false
$installationCommitted = $false
$replaceExisting = $Scenario -in @('upgrade-validation-failure', 'upgrade-success')
$ColorInfo = $ColorSuccess = $ColorWarning = $ColorError = 'White'

function Write-ColorOutput {
    param([string]$Message, [string]$Color)
    Add-Content -LiteralPath (Join-Path $Root 'messages.txt') -Value $Message
}
function New-CanaryDirectory {
    param([string]$Path)
    $null = New-Item -ItemType Directory -Path $Path
    [IO.File]::WriteAllText((Join-Path $Path 'canary.txt'), 'unrelated data')
}
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, [string]$ErrorAction)
    if ($Scenario -eq 'download-failure') {
        New-CanaryDirectory -Path $fullInstallPath
        throw 'Injected download failure after another actor created the target'
    }
    [IO.File]::WriteAllText($OutFile, 'fixture ZIP; archive processing is stubbed')
}
function Test-DownloadChecksum { return $true }
function Assert-SafeReleaseArchive {}
function Unblock-File {}
function Expand-Archive {
    # Only external/archive processing is stubbed; all directory publication,
    # preservation and cleanup operations below use the real filesystem.
    [IO.File]::WriteAllText((Join-Path $stagingPath 'program.txt'), 'new program')
}
function Assert-ReleasePayload {
    param([string]$CandidateRoot)
    if ($CandidateRoot -eq $stagingPath -and $Scenario -eq 'publish-collision') {
        New-CanaryDirectory -Path $fullInstallPath
    }
    if ($CandidateRoot -eq $fullInstallPath -and $Scenario -eq 'late-previous-collision') {
        New-CanaryDirectory -Path $previousPath
    }
    if ($CandidateRoot -eq $fullInstallPath -and $Scenario -eq 'reused-staging-path') {
        New-CanaryDirectory -Path $stagingPath
    }
    if ($CandidateRoot -eq $fullInstallPath -and
        $Scenario -in @('validation-failure', 'upgrade-validation-failure', 'publish-collision')) {
        throw 'Injected post-publication validation failure'
    }
}
if ($replaceExisting) {
    New-CanaryDirectory -Path $fullInstallPath
    foreach ($runtimeName in $retainedRuntimeDirectories) {
        New-CanaryDirectory -Path (Join-Path $fullInstallPath $runtimeName)
    }
}
if ($Scenario -eq 'staging-collision') { New-CanaryDirectory -Path $stagingPath }
if ($Scenario -eq 'previous-collision') { New-CanaryDirectory -Path $previousPath }
if ($Scenario -eq 'download-collision') { [IO.File]::WriteAllText($downloadPath, 'unrelated download') }
'@
    $script:TransactionFixture = Join-Path $TestDrive 'installer-transaction.ps1'
    [IO.File]::WriteAllText($script:TransactionFixture,
        $fixtureSetup + "`n" + $transactions[0].Extent.Text + "`nexit 0`n",
        [Text.UTF8Encoding]::new($false))
}

Describe 'Installer transaction filesystem ownership' {
    It 'preserves a destination created by another actor during <Scenario>' -TestCases @(
        @{ Scenario = 'download-failure' }
        @{ Scenario = 'publish-collision' }
    ) {
        param($Scenario)
        $root = Join-Path $TestDrive $Scenario
        $null = New-Item -ItemType Directory -Path $root
        & $script:TransactionFixture -Root $root -Scenario $Scenario
        $LASTEXITCODE | Should -Be 1
        Get-Content -LiteralPath (Join-Path $root 'installation/canary.txt') -Raw |
            Should -BeExactly 'unrelated data'
        @(Get-ChildItem -LiteralPath (Join-Path $root 'installation') -Force).Count | Should -Be 1
    }

    It 'preserves an occupied transaction path during <Scenario>' -TestCases @(
        @{ Scenario = 'staging-collision'; Canary = 'staging/canary.txt'; Value = 'unrelated data' }
        @{ Scenario = 'previous-collision'; Canary = 'previous/canary.txt'; Value = 'unrelated data' }
        @{ Scenario = 'download-collision'; Canary = 'download.zip'; Value = 'unrelated download' }
    ) {
        param($Scenario, $Canary, $Value)
        $root = Join-Path $TestDrive $Scenario
        $null = New-Item -ItemType Directory -Path $root
        & $script:TransactionFixture -Root $root -Scenario $Scenario
        $LASTEXITCODE | Should -Be 1
        Get-Content -LiteralPath (Join-Path $root $Canary) -Raw | Should -BeExactly $Value
        Test-Path -LiteralPath (Join-Path $root 'installation') | Should -BeFalse
    }

    It 'removes its own newly published payload after validation fails' {
        $root = Join-Path $TestDrive 'validation-failure'
        $null = New-Item -ItemType Directory -Path $root
        & $script:TransactionFixture -Root $root -Scenario 'validation-failure'
        $LASTEXITCODE | Should -Be 1
        Test-Path -LiteralPath (Join-Path $root 'installation') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $root 'staging') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $root 'download.zip') | Should -BeFalse
    }

    It 'preserves an unowned transaction path after publication during <Scenario>' -TestCases @(
        @{ Scenario = 'late-previous-collision'; Canary = 'previous/canary.txt' }
        @{ Scenario = 'reused-staging-path'; Canary = 'staging/canary.txt' }
    ) {
        param($Scenario, $Canary)
        $root = Join-Path $TestDrive $Scenario
        $null = New-Item -ItemType Directory -Path $root
        & $script:TransactionFixture -Root $root -Scenario $Scenario
        $LASTEXITCODE | Should -Be 0
        Get-Content -LiteralPath (Join-Path $root $Canary) -Raw | Should -BeExactly 'unrelated data'
        Get-Content -LiteralPath (Join-Path $root 'installation/program.txt') -Raw | Should -BeExactly 'new program'
    }

    It 'restores the old program and every runtime directory after upgrade validation fails' {
        $root = Join-Path $TestDrive 'upgrade-validation-failure'
        $null = New-Item -ItemType Directory -Path $root
        & $script:TransactionFixture -Root $root -Scenario 'upgrade-validation-failure'
        $LASTEXITCODE | Should -Be 1
        foreach ($relativePath in @('canary.txt', 'Backups/canary.txt', 'Logs/canary.txt', 'Reports/canary.txt')) {
            Get-Content -LiteralPath (Join-Path (Join-Path $root 'installation') $relativePath) -Raw |
                Should -BeExactly 'unrelated data'
        }
        Test-Path -LiteralPath (Join-Path $root 'previous') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $root 'installation/program.txt') | Should -BeFalse
    }

    It 'publishes the new program and retains runtime data during a successful upgrade' {
        $root = Join-Path $TestDrive 'upgrade-success'
        $null = New-Item -ItemType Directory -Path $root
        & $script:TransactionFixture -Root $root -Scenario 'upgrade-success'
        $LASTEXITCODE | Should -Be 0
        Get-Content -LiteralPath (Join-Path $root 'installation/program.txt') -Raw | Should -BeExactly 'new program'
        foreach ($runtimeName in @('Backups', 'Logs', 'Reports')) {
            Get-Content -LiteralPath (Join-Path $root "installation/$runtimeName/canary.txt") -Raw |
                Should -BeExactly 'unrelated data'
        }
        Test-Path -LiteralPath (Join-Path $root 'previous') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $root 'installation/canary.txt') | Should -BeFalse
    }
}
