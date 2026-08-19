#Requires -Version 5.1

<#
.SYNOPSIS
    Generates SHA256 checksums for release files.

.DESCRIPTION
    Creates a CHECKSUMS.sha256 file containing SHA256 hashes of all release files.
    Used for verifying download integrity.

.PARAMETER ReleasePath
    Path to the release folder or ZIP file(s).

.PARAMETER OutputFile
    Output file for checksums. Default: CHECKSUMS.sha256 in the same directory.

.EXAMPLE
    .\Generate-ReleaseChecksums.ps1 -ReleasePath "C:\Release\NoIDPrivacy-v2.2.5"

.EXAMPLE
    .\Generate-ReleaseChecksums.ps1 -ReleasePath ".\NoIDPrivacy-v2.2.5.zip"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReleasePath,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile
)

$ErrorActionPreference = 'Stop'

Write-Host "`n=== NoID Privacy Release Checksum Generator ===" -ForegroundColor Cyan

# Resolve output before enumerating so an existing manifest inside a release
# directory is excluded by its exact full path, not by basename.
$releaseIsDirectory = Test-Path -LiteralPath $ReleasePath -PathType Container
$releaseIsFile = Test-Path -LiteralPath $ReleasePath -PathType Leaf
if (-not $releaseIsDirectory -and -not $releaseIsFile) {
    throw "Path not found: $ReleasePath"
}

# [System.IO.Path]::GetFullPath resolves a relative path against the PROCESS
# working directory, which in Windows PowerShell does not follow Set-Location.
# Test-Path/Get-Item above use the PowerShell provider location, so the script
# hashed the right archive and then wrote its manifest into a different folder -
# leaving a stale CHECKSUMS.sha256 next to the release. Resolve everything
# through the provider so both halves agree.
$resolvedReleasePath = (Resolve-Path -LiteralPath $ReleasePath -ErrorAction Stop).ProviderPath
$basePath = if ($releaseIsDirectory) {
    $resolvedReleasePath.TrimEnd('\', '/')
}
else {
    ([System.IO.Path]::GetDirectoryName($resolvedReleasePath)).TrimEnd('\', '/')
}
if (-not $OutputFile) {
    $OutputFile = Join-Path $basePath "CHECKSUMS.sha256"
}
$outputFullPath = if ([System.IO.Path]::IsPathRooted($OutputFile)) {
    [System.IO.Path]::GetFullPath($OutputFile)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $PWD.ProviderPath $OutputFile))
}
$outputDirectory = [System.IO.Path]::GetDirectoryName($outputFullPath)
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    throw "Checksum output directory does not exist: $outputDirectory"
}

# Determine if path is file or directory. $basePath stays the provider-resolved
# value from above: re-resolving $ReleasePath through GetFullPath here silently
# re-introduced the process-CWD split this script exists to avoid.
if ($releaseIsDirectory) {
    $files = @(Get-ChildItem -LiteralPath $basePath -File -Recurse |
        Where-Object {
            -not ([System.IO.Path]::GetFullPath($_.FullName)).Equals($outputFullPath, [StringComparison]::OrdinalIgnoreCase)
        } |
        Sort-Object -Property FullName)
}
else {
    $files = @(Get-Item -LiteralPath $ReleasePath)
}

if ($files.Count -eq 0) {
    throw 'No eligible release files were found to checksum'
}

Write-Host "Generating checksums for $($files.Count) file(s)..." -ForegroundColor Yellow

$checksums = @()
$checksums += "# NoID Privacy Release Checksums"
$checksums += "# Generated: $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
$checksums += "# Verify with: Get-FileHash -Algorithm SHA256 <file>"
$checksums += ""

foreach ($file in $files) {
    if ($files.Count -eq 1 -and -not $releaseIsDirectory) {
        $relativePath = $file.Name
    }
    else {
        $basePrefix = $basePath + [System.IO.Path]::DirectorySeparatorChar
        $fullName = [System.IO.Path]::GetFullPath($file.FullName)
        if (-not $fullName.StartsWith($basePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "File is outside checksum base path: $fullName"
        }
        $relativePath = $fullName.Substring($basePrefix.Length).Replace('\', '/')
    }

    if ([string]::IsNullOrWhiteSpace($relativePath) -or
        [System.IO.Path]::IsPathRooted($relativePath) -or
        $relativePath -match '(^|/)\.\.(/|$)' -or
        $relativePath -match '[\r\n]') {
        throw "Unsafe relative path cannot be written to checksum manifest: '$relativePath'"
    }

    Write-Host "  Hashing: $relativePath" -ForegroundColor Gray
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $checksums += "$hash  $relativePath"
}

$dataPaths = @($checksums | ForEach-Object {
        $match = [regex]::Match($_, '^[a-f0-9]{64}\s{2}(.+)$')
        if ($match.Success) { $match.Groups[1].Value }
    })
if (@($dataPaths | Group-Object | Where-Object { $_.Count -gt 1 }).Count -gt 0) {
    throw 'Checksum manifest would contain duplicate relative paths'
}

# Use .NET WriteAllText with UTF-8 NO-BOM for cross-tool checksum-parser compatibility
# (sha256sum, certutil, openssl, etc. tolerate BOM but NO-BOM is the canonical convention).
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($outputFullPath, ($checksums -join "`r`n") + "`r`n", $utf8NoBom)

Write-Host "`nChecksums written to: $outputFullPath" -ForegroundColor Green
Write-Host "`nContents:" -ForegroundColor Cyan
Get-Content -LiteralPath $outputFullPath | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== Done ===" -ForegroundColor Cyan
