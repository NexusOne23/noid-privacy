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
    .\Generate-ReleaseChecksums.ps1 -ReleasePath "C:\Release\NoIDPrivacy-v2.2.2"
    
.EXAMPLE
    .\Generate-ReleaseChecksums.ps1 -ReleasePath ".\NoIDPrivacy-v2.2.2.zip"
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

# Determine if path is file or directory
if (Test-Path $ReleasePath -PathType Container) {
    $files = Get-ChildItem -Path $ReleasePath -File -Recurse | Where-Object { $_.Extension -in '.zip', '.exe', '.ps1', '.psm1' }
    $basePath = $ReleasePath
} elseif (Test-Path $ReleasePath -PathType Leaf) {
    $files = Get-Item $ReleasePath
    $basePath = Split-Path $ReleasePath -Parent
} else {
    Write-Error "Path not found: $ReleasePath"
    exit 1
}

if (-not $OutputFile) {
    $OutputFile = Join-Path $basePath "CHECKSUMS.sha256"
}

Write-Host "Generating checksums for $($files.Count) file(s)..." -ForegroundColor Yellow

$checksums = @()
$checksums += "# NoID Privacy Release Checksums"
$checksums += "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)"
$checksums += "# Verify with: Get-FileHash -Algorithm SHA256 <file>"
$checksums += ""

foreach ($file in $files) {
    Write-Host "  Hashing: $($file.Name)" -ForegroundColor Gray
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLower()
    $relativePath = $file.Name
    $checksums += "$hash  $relativePath"
}

$checksums | Out-File -FilePath $OutputFile -Encoding utf8

Write-Host "`nChecksums written to: $OutputFile" -ForegroundColor Green
Write-Host "`nContents:" -ForegroundColor Cyan
Get-Content $OutputFile | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== Done ===" -ForegroundColor Cyan
