#Requires -Version 5.1

<#
.SYNOPSIS
    Bump version number across all project files

.DESCRIPTION
    Reads the current version from the VERSION file, replaces it with the new
    version in all project files, and updates the VERSION file.

    CHANGELOG.md is excluded because it contains historical version entries
    that must not be modified.

.PARAMETER NewVersion
    The new version number (e.g., "2.2.4")

.PARAMETER DryRun
    Preview changes without modifying any files

.EXAMPLE
    .\Bump-Version.ps1 -NewVersion "2.2.4"
    Bump all files from current version to 2.2.4

.EXAMPLE
    .\Bump-Version.ps1 -NewVersion "2.2.4" -DryRun
    Preview what would change without modifying files

.NOTES
    Author: NexusOne23
    The VERSION file at the project root is the single source of truth.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$NewVersion,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# Resolve project root (one level up from Tools/)
$projectRoot = Split-Path $PSScriptRoot -Parent
$versionFile = Join-Path $projectRoot "VERSION"

# Read current version
if (-not (Test-Path $versionFile)) {
    Write-Host "ERROR: VERSION file not found at: $versionFile" -ForegroundColor Red
    exit 1
}

$oldVersion = (Get-Content $versionFile -Raw).Trim()

if (-not ($oldVersion -match '^\d+\.\d+\.\d+$')) {
    Write-Host "ERROR: Invalid version in VERSION file: '$oldVersion'" -ForegroundColor Red
    exit 1
}

if ($oldVersion -eq $NewVersion) {
    Write-Host "ERROR: New version ($NewVersion) is identical to current version ($oldVersion)" -ForegroundColor Red
    exit 1
}

# File extensions to process
$extensions = @("*.ps1", "*.psm1", "*.psd1", "*.json", "*.md", "*.bat", "*.yml")

# Files to exclude (relative to project root)
$excludedFiles = @("CHANGELOG.md")

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NoID Privacy Version Bump" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Current version:  $oldVersion" -ForegroundColor White
Write-Host "  New version:      $NewVersion" -ForegroundColor Green
Write-Host ""

if ($DryRun) {
    Write-Host "  [DRY RUN - No files will be modified]" -ForegroundColor Yellow
    Write-Host ""
}

# Collect all matching files
$allFiles = @()
foreach ($ext in $extensions) {
    $allFiles += Get-ChildItem -Path $projectRoot -Filter $ext -Recurse -File |
        Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }
}

# Process files
$changedFiles = 0
$totalReplacements = 0

foreach ($file in $allFiles) {
    $relativePath = $file.FullName.Substring($projectRoot.Length + 1)

    # Check exclusion list
    $isExcluded = $false
    foreach ($excluded in $excludedFiles) {
        if ($relativePath -eq $excluded) {
            $isExcluded = $true
            break
        }
    }
    if ($isExcluded) {
        Write-Host "  [SKIP] $relativePath (excluded)" -ForegroundColor DarkGray
        continue
    }

    # Read file content
    $content = Get-Content $file.FullName -Raw -Encoding UTF8

    # Count occurrences
    $count = ([regex]::Matches($content, [regex]::Escape($oldVersion))).Count

    if ($count -gt 0) {
        $changedFiles++
        $totalReplacements += $count

        Write-Host "  [BUMP] $relativePath ($count replacement$(if ($count -gt 1) {'s'}))" -ForegroundColor Green

        if (-not $DryRun) {
            $newContent = $content.Replace($oldVersion, $NewVersion)
            [System.IO.File]::WriteAllText($file.FullName, $newContent, [System.Text.UTF8Encoding]::new($false))
        }
    }
}

# Update VERSION file
if (-not $DryRun) {
    [System.IO.File]::WriteAllText($versionFile, "$NewVersion`n", [System.Text.UTF8Encoding]::new($false))
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Files changed:     $changedFiles" -ForegroundColor White
Write-Host "  Total replacements: $totalReplacements" -ForegroundColor White
Write-Host ""

if ($DryRun) {
    Write-Host "  DRY RUN complete. No files were modified." -ForegroundColor Yellow
    Write-Host "  Run without -DryRun to apply changes." -ForegroundColor Yellow
}
else {
    Write-Host "  Version bumped: $oldVersion -> $NewVersion" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor White
    Write-Host "    1. Update CHANGELOG.md with new version section" -ForegroundColor Gray
    Write-Host "    2. Review changes: git diff" -ForegroundColor Gray
    Write-Host "    3. Commit: git add -A && git commit -m 'chore: bump version to $NewVersion'" -ForegroundColor Gray
}

Write-Host ""
