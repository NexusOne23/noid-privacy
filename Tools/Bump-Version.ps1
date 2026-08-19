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
    The new version number (e.g., "2.2.5")

.PARAMETER DryRun
    Preview changes without modifying any files

.EXAMPLE
    .\Bump-Version.ps1 -NewVersion "2.2.5"
    Bump all files from current version to 2.2.5

.EXAMPLE
    .\Bump-Version.ps1 -NewVersion "2.2.5" -DryRun
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

# Files to exclude (relative to project root).
#
# A blanket replace over every *.ps1/*.md/*.yml corrupts three classes of file:
#  - historical documents, whose version IS their identity (release notes,
#    changelog). Rewriting them retitles the provenance of a shipped release.
#  - CI files that reference a versioned path; the rewritten path names a
#    document that does not exist yet and breaks every push.
#  - generated/working trees that are not source at all.
$excludedFiles = @("CHANGELOG.md")

# Path patterns (matched against the project-root-relative path).
$excludedPathPatterns = @(
    '^Docs[\\/]RELEASE-NOTES-.*\.md$'
    '^\.github[\\/]'
    '^Backups[\\/]'
    '^Logs[\\/]'
    '^Reports[\\/]'
    '^dist[\\/]'
    '^publish[\\/]'
)

# Lines carrying a FROZEN legacy-version anchor must never be rewritten: the
# frozen Privacy/Edge restore contracts exist precisely to restore sealed
# sessions from that older version, and renaming them makes the contract
# document and report itself as the version it cannot restore.
$frozenAnchorPattern = '(?i)(frozen|legacy|schema\s*\d)'

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
    if (-not $isExcluded) {
        foreach ($pattern in $excludedPathPatterns) {
            if ($relativePath -match $pattern) { $isExcluded = $true; break }
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
        # Rewrite line by line so a frozen legacy-version anchor can be left
        # alone without excluding the whole file, which usually also carries
        # legitimate current-version strings.
        $newlineSuffix = if ($content.Contains("`r`n")) { "`r`n" } else { "`n" }
        $lines = $content -split "`r?`n"
        $replacedInFile = 0
        $preservedInFile = 0
        for ($index = 0; $index -lt $lines.Count; $index++) {
            $lineMatches = ([regex]::Matches($lines[$index], [regex]::Escape($oldVersion))).Count
            if ($lineMatches -eq 0) { continue }
            if ($lines[$index] -match $frozenAnchorPattern) {
                $preservedInFile += $lineMatches
                Write-Host "         [KEEP] line $($index + 1): frozen legacy anchor left at $oldVersion" -ForegroundColor DarkYellow
                continue
            }
            $lines[$index] = $lines[$index].Replace($oldVersion, $NewVersion)
            $replacedInFile += $lineMatches
        }

        if ($replacedInFile -gt 0) {
            $changedFiles++
            $totalReplacements += $replacedInFile
            Write-Host "  [BUMP] $relativePath ($replacedInFile replacement$(if ($replacedInFile -gt 1) {'s'})$(if ($preservedInFile -gt 0) { ", $preservedInFile frozen anchor(s) kept" }))" -ForegroundColor Green

            if (-not $DryRun) {
                $newContent = ($lines -join $newlineSuffix)
                [System.IO.File]::WriteAllText($file.FullName, $newContent, [System.Text.UTF8Encoding]::new($false))
            }
        }
        elseif ($preservedInFile -gt 0) {
            Write-Host "  [KEEP] $relativePath ($preservedInFile frozen anchor(s) only)" -ForegroundColor DarkYellow
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
