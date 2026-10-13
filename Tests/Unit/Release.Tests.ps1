#Requires -Version 5.1

<#
.SYNOPSIS
    Deterministic release, checksum and transactional-installer regression tests.
#>

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ChecksumTool = Join-Path $script:RepoRoot 'Tools/Generate-ReleaseChecksums.ps1'
    $script:InstallerPath = Join-Path $script:RepoRoot 'install.ps1'
    $script:WorkflowPath = Join-Path $script:RepoRoot '.github/workflows/release-checksums.yml'
    $script:Windows11WorkflowPath = Join-Path $script:RepoRoot '.github/workflows/windows11-bavr.yml'
    $script:Windows11HarnessPath = Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11BavrValidation.ps1'
    $script:StandaloneVerifierHarnessPath = Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11StandaloneVerifierValidation.ps1'
    $script:DecisionMatrixHarnessPath = Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11DecisionMatrix.ps1'
    $script:BaselineParserPath = Join-Path $script:RepoRoot 'Tools/Parse-SecurityBaseline.ps1'
    $script:BaselineProvenancePath = Join-Path $script:RepoRoot 'Tools/Test-SecurityBaselineProvenance.ps1'

    $installerTokens = $null
    $installerParseErrors = $null
    $installerAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:InstallerPath,
        [ref]$installerTokens,
        [ref]$installerParseErrors
    )
    if (@($installerParseErrors).Count -gt 0) {
        throw "Installer parse failure: $($installerParseErrors[0].Message)"
    }
    $archiveGuardAsts = @($installerAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Assert-SafeReleaseArchive'
            }, $true))
    if ($archiveGuardAsts.Count -ne 1) {
        throw "Expected exactly one Assert-SafeReleaseArchive definition, found $($archiveGuardAsts.Count)"
    }
    . ([scriptblock]::Create($archiveGuardAsts[0].Extent.Text))

    $manifestDecoderAsts = @($installerAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'ConvertTo-ChecksumManifestText'
            }, $true))
    if ($manifestDecoderAsts.Count -ne 1) {
        throw "Expected exactly one ConvertTo-ChecksumManifestText definition, found $($manifestDecoderAsts.Count)"
    }
    . ([scriptblock]::Create($manifestDecoderAsts[0].Extent.Text))

    $script:NewArchiveFixture = {
        param(
            [Parameter(Mandatory = $true)] [string]$Path,
            [Parameter(Mandatory = $true)] [array]$Entries
        )

        # Windows PowerShell 5.1 does not guarantee that loading the FileSystem
        # facade also makes the core ZipArchive type visible in a fresh process.
        # Load both assemblies explicitly so this fixture is order-independent.
        Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
        $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($fixture in $Entries) {
                $entry = $archive.CreateEntry([string]$fixture.Path)
                if ($null -ne $fixture.ExternalAttributes) {
                    $entry.ExternalAttributes = [int]$fixture.ExternalAttributes
                }
                if (-not ([string]$fixture.Path).EndsWith('/')) {
                    $entryStream = $entry.Open()
                    try {
                        $entryStream.WriteByte(0x41)
                    }
                    finally {
                        $entryStream.Dispose()
                    }
                }
            }
        }
        finally {
            $archive.Dispose()
            $stream.Dispose()
        }
    }
}

Describe 'Windows 11 26H2 Security Baseline provenance contract' {
    It 'fails closed on source layout/count/parser errors instead of emitting a partial profile' {
        $parser = Get-Content -LiteralPath $script:BaselineParserPath -Raw -Encoding UTF8
        $parser | Should -Match '\$gpoMapping\s*=\s*\[ordered\]@\{'
        $parser | Should -Match '26H2 GPO inventory mismatch'
        $parser | Should -Match 'Computer Registry\.pol presence mismatch'
        $parser | Should -Match '26H2 source count mismatch'
        $parser | Should -Match 'ComputerRegistry\s*=\s*331'
        $parser | Should -Match 'Total\s*=\s*438'
        $parser | Should -Match 'Refusing to overwrite the runtime ParsedSettings profile'
        $parser | Should -Match 'Saving parsed settings transactionally'
        $parser | Should -Match 'Staged output count mismatch'
        $parser | Should -Not -Match 'Write-Warning "(?:Registry\.pol|GptTmpl\.inf|audit\.csv) not found'
    }

    It 'binds the official archive and every embedded artifact to exact hashes' {
        $source = Get-Content -LiteralPath $script:BaselineProvenancePath -Raw -Encoding UTF8
        $source | Should -Match '1328685L'
        $source | Should -Match '369f8dad02485b3fc20be089649a29eb6432a7d0f63cef75addace9685e45d18'
        foreach ($hash in @(
                '0dddae691dbad43ec71f97a84032aaf6eda9ddb4884cb993b37cf6dd86772101',
                'b0f39d0f1e81faf3e752bcbd2ead6f54bbae57b067216cbe9decac3d23e903c2',
                '12fd84ee2ecfcdeb3515d08b9fd4a634d3308be6285a1a79cf77b6a538109e93',
                '5aa03d1be0bf2d454eaef7674a0a72d4e1c17836dc1c7a6646edf2ffb6f03c91',
                '3178f4f031eaef144d23c4435694df2afea75237442a788acf446602120cb3ea'
            )) {
            $source | Should -Match $hash
        }
    }

    It 'keeps verified archive extraction separate from parser output' {
        $source = Get-Content -LiteralPath $script:BaselineProvenancePath -Raw -Encoding UTF8
        $source | Should -Match '\$parsedOutputPath\s*=\s*Join-Path\s+\$temporaryOutput\s+''parsed'''
        $source | Should -Match '-OutputPath\s+\$parsedOutputPath'
        $source | Should -Not -Match '-OutputPath\s+\$temporaryOutput(?:\s|$)'
    }

    It 'enumerates provenance JSON root arrays consistently on Windows PowerShell 5.1' {
        foreach ($tool in @('Test-SecurityBaselineProvenance.ps1', 'Test-EdgeBaselineProvenance.ps1')) {
            $source = Get-Content (Join-Path $script:RepoRoot "Tools/$tool") -Raw
            $source | Should -Match 'foreach \(\$entry in @\(\$parsed\)\) \{ \$entry \}'
        }
    }

    It 'preserves whitespace-only Edge PolicyRules metadata data' {
        $source = Get-Content (Join-Path $script:RepoRoot 'Tools/Parse-EdgeBaseline.ps1') -Raw
        $source | Should -Match '\$document\.PreserveWhitespace\s*=\s*\$true'
        foreach ($property in @('Key', 'Value', 'RegType', 'RegData')) {
            $source | Should -Match ("SelectSingleNode\('{0}'\)\.InnerText" -f $property)
        }
    }

    It 'permits exactly the two documented product deviations' {
        $source = Get-Content -LiteralPath $script:BaselineProvenancePath -Raw -Encoding UTF8
        $source | Should -Match '\$deviationName\s*=\s*''RDVDenyWriteAccess'''
        $source | Should -Match '\[int\]\$sourceDeviation\[0\]\.Data -ne 1'
        $source | Should -Match '\[int\]\$repoDeviation\[0\]\.Data -ne 0'
        $source | Should -Match '\$samplesName\s*=\s*''SubmitSamplesConsent'''
        $source | Should -Match '\[int\]\$sourceSamplesDeviation\[0\]\.Data -ne 3'
        $source | Should -Match '\[int\]\$repoSamplesDeviation\[0\]\.Data -ne 1'
        $source | Should -Match 'DeclaredProductDeviations\s*=\s*2'
    }
}

Describe 'Release checksum contract' {
    It 'hashes the exact release ZIP name consumed by the installer' {
        $releaseDirectory = Join-Path $TestDrive 'single-release'
        $null = New-Item -Path $releaseDirectory -ItemType Directory -Force
        $version = (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'VERSION') -Raw -Encoding UTF8).Trim()
        $zipName = "NoIDPrivacy-v$version.zip"
        $zipPath = Join-Path $releaseDirectory $zipName
        [System.IO.File]::WriteAllBytes($zipPath, [byte[]](1, 2, 3, 4, 5))
        $manifestPath = Join-Path $releaseDirectory 'CHECKSUMS.sha256'

        & $script:ChecksumTool -ReleasePath $zipPath -OutputFile $manifestPath

        $dataLines = @(Get-Content -LiteralPath $manifestPath | Where-Object { $_ -match '^[a-f0-9]{64}\s{2}.+$' })
        $dataLines.Count | Should -Be 1
        $expectedHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $dataLines[0] | Should -Be "$expectedHash  $zipName"
    }

    It 'uses collision-free normalized relative paths for a directory tree' {
        $releaseDirectory = Join-Path $TestDrive 'tree-release'
        $null = New-Item -Path (Join-Path $releaseDirectory 'a') -ItemType Directory -Force
        $null = New-Item -Path (Join-Path $releaseDirectory 'b') -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $releaseDirectory 'a/config.json') -Value '{"a":1}' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $releaseDirectory 'b/config.json') -Value '{"b":2}' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $releaseDirectory 'README.md') -Value 'release' -Encoding UTF8
        $manifestPath = Join-Path $TestDrive 'tree-CHECKSUMS.sha256'

        & $script:ChecksumTool -ReleasePath $releaseDirectory -OutputFile $manifestPath

        $paths = @(Get-Content -LiteralPath $manifestPath | ForEach-Object {
                $match = [regex]::Match($_, '^[a-f0-9]{64}\s{2}(.+)$')
                if ($match.Success) { $match.Groups[1].Value }
            })
        $paths.Count | Should -Be 3
        $paths | Should -Contain 'a/config.json'
        $paths | Should -Contain 'b/config.json'
        $paths | Should -Contain 'README.md'
        @($paths | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0
    }
}

Describe 'Release checksum manifest decoding' {
    BeforeAll {
        $script:ManifestHash = 'a' * 64
        $script:ManifestText = "# NoID Privacy Release Checksums`r`n" +
            "# Verify with: Get-FileHash -Algorithm SHA256 <file>`r`n`r`n" +
            "$script:ManifestHash  NoIDPrivacy-v9.9.9.zip`r`n"
    }

    It 'decodes the octet-stream bytes Windows PowerShell 5.1 returns for a release asset' {
        # GitHub serves CHECKSUMS.sha256 as application/octet-stream, so 5.1
        # hands back a byte array. Casting that array to a string yields
        # decimal numbers and zero parsable checksum lines.
        $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($script:ManifestText)
        $responseBytes -is [byte[]] | Should -BeTrue

        $decoded = ConvertTo-ChecksumManifestText -ResponseContent $responseBytes

        $decoded | Should -BeExactly $script:ManifestText
        $decoded | Should -Match "(?m)^$script:ManifestHash\s{2}NoIDPrivacy-v9\.9\.9\.zip\s*$"
        # Positive control: the previous implementation cast the bytes directly.
        [string]$responseBytes | Should -Not -Match "(?m)^$script:ManifestHash\s"
    }

    It 'passes already-decoded text through unchanged' {
        ConvertTo-ChecksumManifestText -ResponseContent $script:ManifestText |
            Should -BeExactly $script:ManifestText
    }

    It 'drops a leading UTF-8 BOM so the first line stays parsable' {
        $bomText = [char]0xFEFF + $script:ManifestText
        ConvertTo-ChecksumManifestText -ResponseContent $bomText |
            Should -BeExactly $script:ManifestText
    }

    It 'rejects a manifest beyond the processing bound' {
        { ConvertTo-ChecksumManifestText -ResponseContent (New-Object 'byte[]' (1MB + 1)) } |
            Should -Throw -ExpectedMessage '*1 MiB processing bound*'
    }
}

Describe 'Transactional installer contract' {
    It 'rejects non-x64 native platforms before installation' {
        $installerSource = Get-Content -LiteralPath $script:InstallerPath -Raw -Encoding UTF8
        $installerSource | Should -Match 'Get-CimInstance -ClassName Win32_Processor'
        $installerSource | Should -Match '\[int\]\$processorArchitectures\[0\] -ne 9'
        $installerSource | Should -Match 'Windows on Arm \(ARM64\).*not supported'
    }

    It 'downloads the bootstrap from an exact tag for review before local execution' {
        $installerSource = Get-Content -LiteralPath $script:InstallerPath -Raw -Encoding UTF8
        $readme = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'README.md') -Raw -Encoding UTF8
        $version = (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'VERSION') -Raw -Encoding UTF8).Trim()
        $taggedBootstrap = [regex]::Escape("raw.githubusercontent.com/NexusOne23/noid-privacy/v$version/install.ps1")

        $installerSource | Should -Match $taggedBootstrap
        $readme | Should -Match $taggedBootstrap
        $installerSource | Should -Not -Match '(?im)^\s*(?:irm|Invoke-RestMethod)[^\r\n]*\|\s*(?:iex|Invoke-Expression)\b'
        $readme | Should -Not -Match '(?im)^\s*(?:irm|Invoke-RestMethod)[^\r\n]*\|\s*(?:iex|Invoke-Expression)\b'
        # Inspect first, then execute exactly that local file. Windows blocks
        # downloaded scripts by default, so the documented start must launch the
        # inspected path in its own Windows PowerShell 5.1 process instead of
        # relying on the machine-wide execution policy.
        $readme | Should -Match 'Get-Content -LiteralPath \$installer[\s\S]+-File \$installer'
        $installerSource | Should -Match 'Get-Content -LiteralPath \$installer[\s\S]+-File \$installer'
        foreach ($documentedStart in @($readme, $installerSource)) {
            $documentedStart | Should -Match 'WindowsPowerShell\\v1\.0\\powershell\.exe[^\r\n]*-ExecutionPolicy Bypass[^\r\n]*-File \$installer'
        }
    }

    It 'documents process-scoped ZIP launcher bypass without claiming Mark-of-the-Web removal' {
        $readme = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'README.md') -Raw -Encoding UTF8
        $troubleshooting = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Docs/TROUBLESHOOTING.md') -Raw -Encoding UTF8
        $launcher = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Start-NoIDPrivacy.bat') -Raw -Encoding UTF8

        $launcher | Should -Match 'ExecutionPolicy Bypass'
        $launcher | Should -Not -Match 'Unblock-File|Zone\.Identifier'
        $readme | Should -Match 'process-scoped `-ExecutionPolicy Bypass`'
        $readme | Should -Match 'does \*\*not\*\* remove Mark-of-the-Web'
        $troubleshooting | Should -Match 'Unblock-File -LiteralPath \$file -Confirm'
        $readme | Should -Not -Match 'automatically unblocks all files'
    }

    It 'accepts a bounded ordinary archive without extracting it' {
        $archivePath = Join-Path $TestDrive 'safe.zip'
        & $script:NewArchiveFixture -Path $archivePath -Entries @(
            [PSCustomObject]@{ Path = 'NoIDPrivacy/file.txt'; ExternalAttributes = $null }
        )

        { Assert-SafeReleaseArchive -ArchivePath $archivePath } | Should -Not -Throw
        Test-Path -LiteralPath (Join-Path $TestDrive 'NoIDPrivacy') | Should -BeFalse
    }

    It 'rejects unsafe archive entry semantics before extraction' {
        # 0xA1FF0000 (Unix symlink mode in the high word) parses as the Int32 bit
        # pattern that ZipArchiveEntry.ExternalAttributes expects; a [uint32] cast
        # of this literal throws on both PowerShell 5.1 and 7.
        $symlinkAttributes = 0xA1FF0000
        $cases = @(
            [PSCustomObject]@{ Name = 'traversal'; Entries = @([PSCustomObject]@{ Path = '../escape.txt'; ExternalAttributes = $null }) }
            [PSCustomObject]@{ Name = 'ads'; Entries = @([PSCustomObject]@{ Path = 'file.txt:stream'; ExternalAttributes = $null }) }
            [PSCustomObject]@{ Name = 'reserved'; Entries = @([PSCustomObject]@{ Path = 'AUX.txt'; ExternalAttributes = $null }) }
            [PSCustomObject]@{ Name = 'collision'; Entries = @(
                    [PSCustomObject]@{ Path = 'A.txt'; ExternalAttributes = $null }
                    [PSCustomObject]@{ Path = 'a.txt'; ExternalAttributes = $null }
                ) }
            [PSCustomObject]@{ Name = 'file-parent'; Entries = @(
                    [PSCustomObject]@{ Path = 'parent'; ExternalAttributes = $null }
                    [PSCustomObject]@{ Path = 'parent/child.txt'; ExternalAttributes = $null }
                ) }
            [PSCustomObject]@{ Name = 'symlink'; Entries = @(
                    [PSCustomObject]@{ Path = 'link'; ExternalAttributes = $symlinkAttributes }
                ) }
        )

        foreach ($case in $cases) {
            $archivePath = Join-Path $TestDrive "$($case.Name).zip"
            & $script:NewArchiveFixture -Path $archivePath -Entries $case.Entries
            { Assert-SafeReleaseArchive -ArchivePath $archivePath } | Should -Throw
        }
    }

    It 'accepts only an exact tagged ZIP plus exact CHECKSUMS.sha256 asset' {
        $source = Get-Content -LiteralPath $script:InstallerPath -Raw -Encoding UTF8
        $source | Should -Match "release\.tag_name -cnotmatch '\^v\(\\d\+"
        $source | Should -Match 'Where-Object \{ \$_.name -ceq ''CHECKSUMS\.sha256'' \}'
        $source | Should -Match '\$fileCandidate -ceq \$ExpectedRelativePath'
        $source | Should -Match 'ExpectedRelativePath \$zipAssetName'
        $source | Should -Not -Match 'archive/refs/heads/main\.zip'
        $source | Should -Not -Match 'Using main branch instead'
    }

    It 'validates and unblocks staging before replacing the existing installation' {
        $source = Get-Content -LiteralPath $script:InstallerPath -Raw -Encoding UTF8
        $archiveIndex = $source.IndexOf('Assert-SafeReleaseArchive -ArchivePath $downloadPath')
        $extractIndex = $source.IndexOf('Expand-Archive -LiteralPath $downloadPath')
        $validateIndex = $source.IndexOf('Assert-ReleasePayload -CandidateRoot $candidateRoot')
        $unblockIndex = $source.IndexOf('Unblock-File -LiteralPath $scriptFile.FullName')
        $moveOldIndex = $source.IndexOf('[System.IO.Directory]::Move($fullInstallPath, $previousPath)')
        $moveNewIndex = $source.IndexOf('[System.IO.Directory]::Move($candidateRoot, $fullInstallPath)')
        $moveRuntimeIndex = $source.IndexOf('[System.IO.Directory]::Move($previousRuntimePath, $newRuntimePath)')
        $deleteOldIndex = $source.IndexOf('Remove-Item -LiteralPath $previousPath -Recurse -Force -ErrorAction Stop')

        # Every index must be PRESENT before it can be ordered. IndexOf returns
        # -1 for a construct that was deleted outright, and -1 is less than any
        # real index, so the ordering chain below happily "passed" for an
        # installer whose Unblock-File loop had simply been removed - Mark-of-the-
        # Web then stayed on every extracted engine file.
        foreach ($orderedIndex in @(
                @{ Name = 'archive';     Value = $archiveIndex }
                @{ Name = 'extract';     Value = $extractIndex }
                @{ Name = 'validate';    Value = $validateIndex }
                @{ Name = 'unblock';     Value = $unblockIndex }
                @{ Name = 'moveOld';     Value = $moveOldIndex }
                @{ Name = 'moveNew';     Value = $moveNewIndex }
                @{ Name = 'moveRuntime'; Value = $moveRuntimeIndex }
                @{ Name = 'deleteOld';   Value = $deleteOldIndex }
            )) {
            $orderedIndex.Value | Should -BeGreaterThan -1 `
                -Because "the installer must still contain the '$($orderedIndex.Name)' step at all"
        }

        $archiveIndex | Should -BeLessThan $extractIndex
        $extractIndex | Should -BeLessThan $validateIndex
        $validateIndex | Should -BeLessThan $moveOldIndex
        $unblockIndex | Should -BeLessThan $moveOldIndex
        $moveOldIndex | Should -BeLessThan $moveNewIndex
        $moveNewIndex | Should -BeLessThan $moveRuntimeIndex
        $moveRuntimeIndex | Should -BeLessThan $deleteOldIndex
        $moveNewIndex | Should -BeLessThan $deleteOldIndex
    }

    It 'retains every BAVR/runtime directory across upgrades and returns it before rollback cleanup' {
        $source = Get-Content -LiteralPath $script:InstallerPath -Raw -Encoding UTF8
        $source | Should -Match "retainedRuntimeDirectories = @\('Backups', 'Logs', 'Reports'\)"
        $source | Should -Match "forbiddenRuntimeDirectory in @\('Backups', 'Logs', 'Reports'\)"

        $moveToNew = $source.IndexOf('[System.IO.Directory]::Move($previousRuntimePath, $newRuntimePath)')
        $moveBack = $source.IndexOf('[System.IO.Directory]::Move($newRuntimePath, $previousRuntimePath)')
        $removeIncompleteNew = $source.IndexOf('Remove-Item -LiteralPath $fullInstallPath -Recurse -Force -ErrorAction Stop')

        $moveToNew | Should -BeGreaterThan -1
        $moveBack | Should -BeGreaterThan $moveToNew
        $moveBack | Should -BeLessThan $removeIncompleteNew
        $source | Should -Match 'retainedDataRollbackFailed'
    }

    It 'rejects archive traversal, ADS, Windows aliases, links, collisions and resource exhaustion before extraction' {
        $source = Get-Content -LiteralPath $script:InstallerPath -Raw -Encoding UTF8
        $source | Should -Match 'function Assert-SafeReleaseArchive'
        $source | Should -Match '\[System\.IO\.Path\]::IsPathRooted\(\$rawPath\)'
        $source | Should -Match '\$rawPath -match '':'''
        $source | Should -Match '\$segment -eq ''\.\.'''
        $source | Should -Match 'CON\|PRN\|AUX\|NUL'
        $source | Should -Match 'OrdinalIgnoreCase'
        $source | Should -Match 'duplicate/case-colliding path'
        $source | Should -Match '0xA000'
        $source | Should -Match 'FileAttributes\]::ReparsePoint'
        $source | Should -Match '\$maxArchiveBytes\s*=\s*128MB'
        $source | Should -Match '\$maxExpandedBytes\s*=\s*512MB'
        $source.IndexOf('Assert-SafeReleaseArchive -ArchivePath $downloadPath') |
            Should -BeLessThan $source.IndexOf('Expand-Archive -LiteralPath $downloadPath')
    }

    It 'pins both release asset URLs to the exact HTTPS GitHub repository path' {
        $source = Get-Content -LiteralPath $script:InstallerPath -Raw -Encoding UTF8
        $source | Should -Match 'function Assert-ReleaseAssetUrl'
        $source | Should -Match 'https://github\.com/NexusOne23/noid-privacy/releases/download/\$Tag/\$AssetName'
        $source | Should -Match '\$candidateUri\.Scheme -cne ''https'''
        $source | Should -Match '\$candidateUri\.Host -cne ''github\.com'''
        $source | Should -Match 'Assert-ReleaseAssetUrl -Url \$downloadUrl'
        $source | Should -Match 'Assert-ReleaseAssetUrl -Url \$checksumUrl'
        $source | Should -Match '\[long\]\$zipAsset\[0\]\.size -le 0[\s\S]+-gt 128MB'
        $source | Should -Match '\[long\]\$checksumAssets\[0\]\.size -le 0[\s\S]+-gt 1MB'
        $source | Should -Match 'Checksum manifest is empty or exceeds the 1 MiB processing bound'
    }

    It 'rejects destination reparse ancestors and unexpected operation paths' {
        $source = Get-Content -LiteralPath $script:InstallerPath -Raw -Encoding UTF8
        $source | Should -Match 'Installation path traverses a reparse point'
        $source | Should -Match 'targets the users root or another user profile'
        $source | Should -Match 'protected shared/system root'
        $source | Should -Match 'Per-operation staging or rollback path unexpectedly already exists'
        $source | Should -Match 'if \(\$locationPushed\)[\s\S]+Pop-Location'
        $source | Should -Match '\$response = Read-Host[\s\S]{0,160}\$response = \$response\.Trim\(\)\.ToUpperInvariant\(\)'
    }

    It 'keeps a rollback path until post-move validation succeeds and reports rollback failure' {
        $source = Get-Content -LiteralPath $script:InstallerPath -Raw -Encoding UTF8
        $source | Should -Match 'Assert-ReleasePayload -CandidateRoot \$fullInstallPath'
        $source | Should -Match '\[System\.IO\.Directory\]::Move\(\$previousPath, \$fullInstallPath\)'
        $source | Should -Match 'automatic rollback was incomplete'
        $source | Should -Match 'Previous installation remains at:'
        $source | Should -Not -Match 'Installation failed without replacing the previous installation'
    }

    It 'launcher elevation never interpolates caller arguments into PowerShell command text' {
        $launcher = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Start-NoIDPrivacy.bat') -Raw -Encoding UTF8
        $launcher | Should -Not -Match '%\*'
        $launcher | Should -Match 'NOID_INTERACTIVE_SCRIPT'
        $launcher | Should -Match '\$env:NOID_INTERACTIVE_SCRIPT'
        $launcher | Should -Match 'Start-Process[\s\S]+-ErrorAction Stop'
        $launcher | Should -Match 'set "NOID_EXIT_CODE=%ERRORLEVEL%"[\s\S]+exit /b %NOID_EXIT_CODE%'
    }
}

Describe 'Release tag and version alignment' {
    It 'checks out the requested tag and rejects VERSION drift before packaging' {
        $workflow = Get-Content -LiteralPath $script:WorkflowPath -Raw -Encoding UTF8
        $workflow | Should -Match 'Checkout exact target tag[\s\S]+ref: \$\{\{ steps\.resolve_tag\.outputs\.tag \}\}'
        $workflow | Should -Match '\$tag -cne "v\$version"'
        $workflow | Should -Match 'Get-FileHash -LiteralPath \$zipFile -Algorithm SHA256'
        $workflow | Should -Match '\$dataLines\.Count -ne 1 -or \$matchingLines\.Count -ne 1'
    }

    It 'keeps production manifests, runtime config, installer and module template on VERSION' {
        $version = (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'VERSION') -Raw -Encoding UTF8).Trim()
        $config = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        [string]$config.version | Should -Be $version

        foreach ($module in @('SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI', 'EdgeHardening', 'AdvancedSecurity')) {
            $manifest = Test-ModuleManifest -Path (Join-Path $script:RepoRoot "Modules/$module/$module.psd1") -ErrorAction Stop
            $manifest.Version.ToString() | Should -Be $version
        }

        $installer = Get-Content -LiteralPath $script:InstallerPath -Raw -Encoding UTF8
        $template = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Modules/_ModuleTemplate/ModuleTemplate.psm1') -Raw -Encoding UTF8
        $installer | Should -Match ([regex]::Escape("Version: $version"))
        $template | Should -Match ([regex]::Escape("`$script:ModuleVersion = `"$version`""))
    }

    It 'keeps the public signing boundary release-stable rather than roadmap-based' {
        $security = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'SECURITY.md') -Raw -Encoding UTF8
        $framework = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core/Framework.ps1') -Raw -Encoding UTF8
        $asrRules = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Modules/ASR/Config/ASR-Rules.json') -Raw -Encoding UTF8
        $aiApplicability = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Docs/WINDOWS-AI-APPLICABILITY.md') -Raw -Encoding UTF8
        $security | Should -Match 'This standalone engine repository distributes reviewed source scripts rather than Authenticode-signed script artifacts'
        $security | Should -Not -Match 'not yet individually Authenticode-signed'
        $security | Should -Not -Match 'script signing is on the roadmap'
        (([char]0x23F3) + ' **Code Signing**') | Should -Match '\u23F3\s*\*\*Code Signing'
        $security | Should -Not -Match '\u23F3\s*\*\*Code Signing'
        $security | Should -Not -Match 'pre-release requirement'
        $framework | Should -Not -Match 'Not yet implemented'
        $framework | Should -Match 'Implementation unavailable'
        # ASR rule warnings describe current behavior only, never a roadmap.
        $roadmapPattern = '(?i)not yet in TVM|planned|coming soon'
        'New rule - not yet in TVM' | Should -Match $roadmapPattern
        $asrRules | Should -Not -Match $roadmapPattern
        # Microsoft's ASR rules reference makes no TVM coverage statement, so the
        # rule metadata must not claim one either.
        $asrRules | Should -Not -Match '\bTVM\b'
        $aiApplicability | Should -Not -Match 'therefore planned on Home'
        $aiApplicability | Should -Match 'applicability planner therefore includes it on Home'
    }

    It 'keeps every Markdown surface free of mutable release-state and own Git identities' {
        $unfinishedPattern = '(?i)\b(unreleased|work[ -]?in[ -]?progress|WIP|TODO|TBD|coming soon|not yet released|release pending|signing pending|signing open|release gate open)\b'
        $ownGitIdentityPattern = '(?i)\b(Shell|Pro GUI|HEAD|source commit|source tree|build commit|build tree)\b[^\r\n]{0,80}\b[0-9a-f]{40}\b'
        'work in progress' | Should -Match $unfinishedPattern
        ('source commit ' + ('a' * 40)) | Should -Match $ownGitIdentityPattern

        $violations = [System.Collections.Generic.List[string]]::new()
        # Skip only Git's own directory and local runtime output; .github
        # templates are public Markdown and stay in scope.
        $excludedRoots = @('.git', 'Backups', 'Logs', 'Reports', 'dist') | ForEach-Object {
            (Join-Path $script:RepoRoot $_) + [IO.Path]::DirectorySeparatorChar
        }
        foreach ($file in @(Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -File -Filter '*.md')) {
            if (@($excludedRoots | Where-Object { $file.FullName.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) { continue }
            $lineNumber = 0
            foreach ($line in Get-Content -LiteralPath $file.FullName -Encoding UTF8) {
                $lineNumber++
                if ($line -match $unfinishedPattern -or $line -match $ownGitIdentityPattern) {
                    $violations.Add("$($file.FullName):$lineNumber")
                }
            }
        }
        $violations | Should -BeNullOrEmpty
    }
}

Describe 'Windows 11 client BAVR release gate' {
    It 'uses only an explicitly confirmed self-hosted disposable Windows 11 runner' {
        $workflow = Get-Content -LiteralPath $script:Windows11WorkflowPath -Raw -Encoding UTF8
        $workflow | Should -Match 'workflow_dispatch:'
        $workflow | Should -Match "confirm_disposable_vm:"
        $workflow | Should -Match "DISPOSABLE-WINDOWS11-VM"
        $workflow | Should -Match 'runs-on:\s*\[self-hosted, Windows, X64, noid-windows11-disposable\]'
        $workflow | Should -Not -Match 'runs-on:\s*windows-latest'
        $workflow | Should -Match "NOID_DISPOSABLE_VM:\s*'true'"
    }

    It 'executes client integration tests on self-hosted Windows and fails on any skipped release test' {
        $workflow = Get-Content -LiteralPath $script:Windows11WorkflowPath -Raw -Encoding UTF8
        $runner = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Run-Tests.ps1') -Raw -Encoding UTF8
        $hostedWorkflow = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/workflows/pester-tests.yml') -Raw -Encoding UTF8
        $integrationFiles = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'Tests/Integration') -Filter '*.Tests.ps1')

        $workflow | Should -Match 'Run-Tests\.ps1[^\r\n]+-RequireZeroSkipped'
        $runner | Should -Match '\[switch\]\$RequireZeroSkipped'
        $runner | Should -Match '\$RequireZeroSkipped -and \[int\]\$testResults\.SkippedCount -gt 0'
        foreach ($file in $integrationFiles) {
            $source = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
            if ($source -match '-Skip:') {
                $source | Should -Match "RUNNER_ENVIRONMENT -ne 'self-hosted'" `
                    -Because "$($file.Name) must execute its Windows tests in the self-hosted release gate"
                $source | Should -Not -Match '-Skip:\(\$env:GITHUB_ACTIONS -eq ''true''\s*-or'
            }
        }
        $hostedWorkflow | Should -Match '\$expectedHostedSkips = 13'
        $hostedWorkflow | Should -Match "RUNNER_ENVIRONMENT -ne 'github-hosted'"
    }

    It 'classifies the optional Weather/Widgets package separately from protected AppX packages' {
        $harness = Get-Content -LiteralPath $script:DecisionMatrixHarnessPath -Raw -Encoding UTF8
        $harness | Should -Match '\$optionalRemoveApps\s*=\s*@\(\$catalog\.OptionalRemoveApps'
        $harness | Should -Match 'elseif \(\$catalogName -in \$optionalRemoveApps\)[\s\S]{0,100}''OptionalRemovable'''
        $harness | Should -Match "else \{\s*'Protected'"
    }

    It 'admits exact 24H2/25H2/26H2 clients and rejects Server, domain, service-session and ambiguous build contexts' {
        $harness = Get-Content -LiteralPath $script:Windows11HarnessPath -Raw -Encoding UTF8
        $harness | Should -Match '#Requires -RunAsAdministrator'
        $harness | Should -Match '\$os\.ProductType\s*-ne\s*1'
        $harness | Should -Match '\$computer\.PartOfDomain'
        $harness | Should -Match 'same Explorer session'
        $harness | Should -Match '\$supported24H2Profile\s*=\s*\$displayVersion\s*-ceq\s*''24H2''\s*-and\s*\$build\s*-in\s*26100\.\.26199'
        $harness | Should -Match '\$supported25H2Profile\s*=\s*\$displayVersion\s*-ceq\s*''25H2''\s*-and\s*\$build\s*-in\s*26200\.\.26299'
        $harness | Should -Match '\$supported26H2Profile\s*=\s*\$displayVersion\s*-ceq\s*''26H2''\s*-and\s*\$build\s*-in\s*26300\.\.27999'
        $harness | Should -Match '\$supportedProfile\s*=\s*\$supported24H2Profile\s*-or\s*\$supported25H2Profile\s*-or\s*\$supported26H2Profile'
    }

    It 'keeps every full-product Windows runner open to exact 24H2, 25H2 and 26H2 profiles' {
        foreach ($path in @(
                $script:Windows11HarnessPath,
                $script:StandaloneVerifierHarnessPath,
                $script:DecisionMatrixHarnessPath
            )) {
            $harness = Get-Content -LiteralPath $path -Raw -Encoding UTF8
            $harness | Should -Match '\$supported24H2Profile\s*=\s*\$displayVersion\s*-ceq\s*''24H2''\s*-and\s*\$build\s*-in\s*26100\.\.26199'
            $harness | Should -Match '\$supported25H2Profile\s*=\s*\$displayVersion\s*-ceq\s*''25H2''\s*-and\s*\$build\s*-in\s*26200\.\.26299'
            $harness | Should -Match '\$supported26H2Profile\s*=\s*\$displayVersion\s*-ceq\s*''26H2''\s*-and\s*\$build\s*-in\s*26300\.\.27999'
            $harness | Should -Match '24H2/26100\.\.26199'
            $harness | Should -Match '25H2/26200\.\.26299'
            $harness | Should -Match '26H2/26300\.\.27999'
        }
    }

    It 'keeps every current 26H2 product statement free of a preview or reduced-support qualifier' {
        $violations = [System.Collections.Generic.List[string]]::new()
        $textExtensions = @('.md', '.ps1', '.psm1', '.psd1', '.json', '.txt')
        $expectedVersion = (
            Get-Content -LiteralPath (Join-Path $script:RepoRoot 'VERSION') -Raw -Encoding UTF8
        ).Trim()
        $changeLogPath = Join-Path $script:RepoRoot 'CHANGELOG.md'
        $releaseNotesRoot = Join-Path $script:RepoRoot 'Docs'
        $currentReleaseNotesPath = Join-Path $releaseNotesRoot "RELEASE-NOTES-$expectedVersion.md"
        (Test-Path -LiteralPath $currentReleaseNotesPath -PathType Leaf) | Should -BeTrue
        $qualifiers = 'preview|\bbeta\b|pre-?release|unreleased|Experimental|unvalidated|not release-approved|readiness'
        $reducedSupportPattern = "(?i)(26H2.*($qualifiers)|($qualifiers).*26H2)"
        foreach ($sample in @('Windows 11 26H2 beta', '26H2 Preview build', 'Unreleased 26H2 profile', '26H2 (pre-release)')) {
            $sample | Should -Match $reducedSupportPattern
        }
        'Windows 11 24H2, 25H2 and 26H2 are all supported releases' | Should -Not -Match $reducedSupportPattern
        # Local runtime output (for example a retained 2.2.5 backup manifest)
        # is user data, not product text.
        $runtimeRoots = @('Backups', 'Logs', 'Reports', 'dist') | ForEach-Object {
            (Join-Path $script:RepoRoot $_) + [IO.Path]::DirectorySeparatorChar
        }
        $files = @(Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -File -Force |
                Where-Object {
                    $historicalReleaseNotes =
                        $_.DirectoryName -ceq $releaseNotesRoot -and
                        $_.Name -match '^RELEASE-NOTES-[0-9]+[.][0-9]+[.][0-9]+[.]md$' -and
                        $_.FullName -cne $currentReleaseNotesPath
                    $fullName = $_.FullName
                    $_.Extension -in $textExtensions -and
                    $_.FullName -notlike (Join-Path $script:RepoRoot '.git*') -and
                    $_.FullName -notlike (Join-Path $script:RepoRoot 'Tests*') -and
                    @($runtimeRoots | Where-Object { $fullName.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0 -and
                    $_.FullName -cne $changeLogPath -and
                    -not $historicalReleaseNotes
                })

        foreach ($file in $files) {
            $lineNumber = 0
            foreach ($line in Get-Content -LiteralPath $file.FullName -Encoding UTF8) {
                $lineNumber++
                if ($line -match $reducedSupportPattern) {
                    $violations.Add("$($file.FullName):$lineNumber")
                }
            }
        }

        # CHANGELOG.md deliberately preserves historical release state. Scan
        # only its first release section and bind that section to VERSION so a
        # future release cannot leave this guard silently checking old text.
        $changeLog = Get-Content -LiteralPath $changeLogPath -Raw -Encoding UTF8
        $currentSection = [regex]::Match(
            $changeLog,
            '(?ms)^## \[(?<version>[0-9]+[.][0-9]+[.][0-9]+)\].*?(?=^## \[|\z)'
        )
        $currentSection.Success | Should -BeTrue
        $currentSection.Groups['version'].Value | Should -BeExactly $expectedVersion
        $lineNumber = 0
        foreach ($line in @($currentSection.Value -split "`r?`n")) {
            $lineNumber++
            if ($line -match $reducedSupportPattern) {
                $violations.Add("${changeLogPath}:${expectedVersion}:$lineNumber")
            }
        }

        $violations | Should -BeNullOrEmpty
    }

    It 'preserves the historical 2.2.5 platform boundary without rewriting release history' {
        $changeLog = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'CHANGELOG.md') -Raw -Encoding UTF8
        $releaseNotes = Get-Content -LiteralPath (
            Join-Path $script:RepoRoot 'Docs/RELEASE-NOTES-2.2.5.md'
        ) -Raw -Encoding UTF8

        $changeLog | Should -Match 'The 425-target Microsoft Security Baseline uses one safety-reviewed BAVR path[\s\S]{0,180}26H2 preview[\s\S]{0,100}Experimental; it is not release-approved[.]'
        $releaseNotes | Should -Match 'Windows 11 26H2 is consistently admitted only as an Experimental full-BAVR apply path[\s\S]{0,180}runtime gate remains Windows 11 Pro 25H2[.]'
        $changeLog | Should -Not -Match 'This historical 2[.]2[.]5 entry is superseded by 2[.]2[.]6'
        $releaseNotes | Should -Not -Match 'historical 2[.]2[.]5 platform boundary is superseded'
    }

    It 'documents the Remote UAC breaking change and the point-in-time restore boundary' {
        $changeLog = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'CHANGELOG.md') -Raw -Encoding UTF8
        $releaseNotes = Get-Content -LiteralPath (
            Join-Path $script:RepoRoot 'Docs/RELEASE-NOTES-2.2.6.md'
        ) -Raw -Encoding UTF8
        $troubleshooting = Get-Content -LiteralPath (
            Join-Path $script:RepoRoot 'Docs/TROUBLESHOOTING.md'
        ) -Raw -Encoding UTF8
        $controlReference = Get-Content -LiteralPath (
            Join-Path $script:RepoRoot 'Docs/SECURITY-PRIVACY-CONTROLS.md'
        ) -Raw -Encoding UTF8

        $changeLog | Should -Match '### Breaking[\s\S]{0,1000}LocalAccountTokenFilterPolicy=0[\s\S]{0,600}-SkipStandaloneDelta'
        $releaseNotes | Should -Match '## Remote UAC compatibility change[\s\S]{0,1200}Access denied'
        $troubleshooting | Should -Match 'Remote SMB/WMI/WinRM says "Access denied"[\s\S]{0,1400}LocalAccountTokenFilterPolicy=1'
        $controlReference | Should -Match 'Point-in-time restore[\s\S]{0,1800}Recovery/PointInTimeRestore'
        $controlReference | Should -Match 'windows/configuration/point-in-time-restore'
        $releaseNotes | Should -Match '## Point-in-time restore[\s\S]{0,1800}BitLocker recovery key[\s\S]{0,500}Recall'
    }

    It 'applies, verifies and restores each module through one explicit sealed session' {
        $harness = Get-Content -LiteralPath $script:Windows11HarnessPath -Raw -Encoding UTF8
        foreach ($module in @(
                'SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI',
                'EdgeHardening', 'AdvancedSecurity'
            )) {
            $harness | Should -Match ([regex]::Escape("'$module'"))
        }
        $harness | Should -Match '\$newSessions\.Count -ne 1'
        $harness | Should -Match '''-RestoreSessionPath'', \$session\.FullName'
        $harness | Should -Match '\$restoreExitCode -ne 0'
        $harness | Should -Match '\$records\.Count -eq \$Modules\.Count'
        $harness | Should -Match 'Result = ''Failed''; Error = \$failureMessage'
        $harness | Should -Match '& \$windowsPowerShell @applyArguments'
        $harness | Should -Match '& \$windowsPowerShell @restoreArguments'
        $harness | Should -Match 'Invoke-IndependentStateFingerprint'
        $harness | Should -Match '\$stateProcessOutput\s*=\s*@\(& \$windowsPowerShell @arguments 2>&1\)'
        $harness | Should -Match 'SessionFilesUnchanged'
        $harness | Should -Match '\[string\]\$ConfigurationPath'
        $harness | Should -Match 'ConfigurationSha256'
        $harness | Should -Match 'New-ModuleScopedConfiguration'
        $harness | Should -Match 'EffectiveConfigurationSha256'
        $harness | Should -Match '-EffectiveConfigurationPath \$effectiveConfiguration\.Path'
        $harness | Should -Match '\$effectiveConfigurationSha256\s*=\s*\(Get-FileHash'
        $harness | Should -Match '\[string\]\$contract\.configSha256\s*-cne\s*\$effectiveConfigurationSha256'
        $harness | Should -Not -Match '\[string\]\$contract\.configSha256\s*-cne\s*\$configSha256'
        $harness | Should -Not -Match 'Start-Process'

        $workflow = Get-Content -LiteralPath $script:Windows11WorkflowPath -Raw -Encoding UTF8
        $workflow | Should -Match '-EvidenceDirectory \.\\Windows11-BAVR-State'
        $workflow | Should -Match 'Windows11-BAVR-State/\*\*/\*\.json'
    }

    It 'runs the standalone verifier through backup deletion, named drift and exact restore' {
        $harness = Get-Content -LiteralPath $script:StandaloneVerifierHarnessPath -Raw -Encoding UTF8
        $harness | Should -Match '#Requires -RunAsAdministrator'
        $harness | Should -Match 'NOID_DISPOSABLE_VM -ne ''true'''
        $harness | Should -Match 'Privacy\.mode=Strict'
        $harness | Should -Match '\$expectedPrivacyCount -ne 90'
        $harness | Should -Match '\$privacyCategories\s*=\s*@\(\$Verification\.Document\.AllSettings'
        $harness | Should -Match '\$intentional\s*=\s*\[int\]\$privacyCategory\.NotCheckedDeliberate'
        $harness | Should -Not -Match 'Assert-SelectedPrivacyVerifierUx[^\r\n]+-Passed 54'
        $harness | Should -Not -Match 'Assert-SelectedPrivacyVerifierUx[^\r\n]+-NotApplicable 34'
        $harness | Should -Match '<table class="settings-table">'
        $harness | Should -Match 'toggleModule'
        $harness | Should -Match ([regex]::Escape(
                "'-File', `$entryPoint, '-Module', 'All'"))
        $harness | Should -Match 'Remove-Item -LiteralPath \$session\.FullName -Recurse -Force'
        $harness | Should -Match 'Standalone verifier result changed after deleting the latest backup session'
        $harness | Should -Match '\$driftName = ''DisabledByGroupPolicy'''
        $harness | Should -Match '\$driftPath = ''HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo'''
        $harness | Should -Match 'did not report exactly one named \$driftName deviation'
        $harness | Should -Match 'Invoke-StandaloneRestore -SessionPath \$archivedSession'
        $harness | Should -Match 'Compare-IndependentStateFingerprint'
        $harness | Should -Match 'Post-Restore standalone verification retained a stale Apply claim or reported a false green result'
        $harness | Should -Not -Match '''-AppliedSessionPath'''
        $harness | Should -Not -Match '''-ConfigPath'', \$configurationFullPath[\s\S]{0,100}Invoke-StandaloneVerification'
    }

    It 'exposes exact-session automation with success 0 and restore failure 4' {
        $cli = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $cli | Should -Match "ParameterSetName = 'Restore'"
        $cli | Should -Match '\[string\]\$RestoreSessionPath'
        $cli | Should -Match 'Resolve-Path -LiteralPath \$RestoreSessionPath'
        $cli | Should -Match 'Restore-Session @restoreArguments'
        $cli | Should -Match 'SessionPath=\$resolvedRestoreSession;NoReboot=\$true'
        $cli | Should -Match 'exit \$script:EXIT_SUCCESS'
        $cli | Should -Match 'exit \$script:EXIT_ERROR_MODULE'
    }

    It 'preserves every documented process exit through embedded call-operator hosts' {
        $cli = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'NoIDPrivacy.ps1') -Raw -Encoding UTF8
        $exitStatements = [regex]::Matches($cli, '(?m)^\s*exit\s+(?<code>[^\r\n]+?)\s*$')
        $hostPairedExits = [regex]::Matches($cli,
            '(?m)^\s*Request-NoIDHostExit -ExitCode (?<code>[^\r\n]+?)\s*\r?\n\s*exit\s+\k<code>\s*$')

        $exitStatements.Count | Should -BeGreaterThan 0
        $hostPairedExits.Count | Should -Be $exitStatements.Count
        # The single SetShouldExit call lives in Request-NoIDHostExit, which
        # skips it only for an interactive console session.
        ([regex]::Matches($cli, '\$host\.SetShouldExit\(')).Count | Should -Be 1
        $cli | Should -Match 'Test-NoIDInteractiveConsoleSession'
    }
}

Describe 'Generated test-result accounting' {
    It 'CI syntax gates parse every PowerShell file type and reject zero discovery' {
        $workflow = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/workflows/ci.yml') -Raw -Encoding UTF8
        ([regex]::Matches($workflow, '\$_.Extension -in @\(''\.ps1'', ''\.psm1'', ''\.psd1''\)')).Count | Should -Be 2
        ([regex]::Matches($workflow, 'syntax discovery returned zero files')).Count | Should -Be 2
        $workflow | Should -Not -Match 'Filter "\*\.ps1" -Recurse -ErrorAction SilentlyContinue'
    }

    It 'fails every local and hosted test path when discovery returns zero tests' {
        $runner = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Run-Tests.ps1') -Raw -Encoding UTF8
        $allRunner = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Tests/Run-AllTests.ps1') -Raw -Encoding UTF8
        $workflow = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/workflows/pester-tests.yml') -Raw -Encoding UTF8

        $runner | Should -Match 'No test directories found[\s\S]{0,100}exit 1'
        $runner | Should -Match '\$testResults\.TotalCount -eq 0[\s\S]{0,120}exit 1'
        $allRunner | Should -Match '\$testResults\.TotalCount -eq 0[\s\S]{0,120}exit 1'
        # The unit step guards a positive coverage FLOOR rather than merely
        # "greater than zero", because a removed test file lowers the total without
        # ever reaching zero. The integration step keeps the zero check.
        $workflow | Should -Match '\$results\.TotalCount -lt \$unitTestFloor'
        $workflow | Should -Match '\$unitTestFloor = \d+'
        ([regex]::Matches($workflow, '\$results\.TotalCount -eq 0')).Count | Should -Be 1
    }

    It 'renders CI summary counts from result XML instead of hard-coded totals' {
        $workflow = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/workflows/pester-tests.yml') -Raw -Encoding UTF8
        $workflow | Should -Match '\[xml\]\$xml = Get-Content \$f\.FullName'
        $workflow | Should -Match '\$\(\$r\.total\) total'
        $workflow | Should -Match '\$\(\$r\.''not-run''\) skipped'
    }
}

Describe 'Monotonic wait deadlines' {
    It 'bounds every product wait with a monotonic timer instead of the adjustable wall clock' {
        # A time-service correction during a run (for example the first sync
        # on a device with a wrong clock) must not end or extend a wait early.
        $wallClockDeadline = '\[DateTime\]::(Utc)?Now\.Add(Milliseconds|Seconds|Minutes)\(|\(Get-Date\)\.Add(Milliseconds|Seconds|Minutes)\('
        '$deadline = [DateTime]::UtcNow.AddSeconds(15)' | Should -Match $wallClockDeadline
        $productFiles = @(Get-ChildItem -LiteralPath $script:RepoRoot -File -Filter '*.ps1') + @(
            foreach ($folder in @('Core', 'Modules', 'Tools', 'Utils')) {
                Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot $folder) -Recurse -File -Include '*.ps1', '*.psm1'
            })
        $productFiles.Count | Should -BeGreaterThan 100
        $offenders = @($productFiles | Select-String -Pattern $wallClockDeadline | ForEach-Object {
                '{0}:{1}' -f $_.Path.Substring($script:RepoRoot.Length + 1), $_.LineNumber
            })
        $offenders | Should -BeNullOrEmpty
    }
}
