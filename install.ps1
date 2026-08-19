#Requires -Version 5.1

<#
.SYNOPSIS
    NoID Privacy - Reviewed Bootstrap Installer

.DESCRIPTION
    Downloads and installs the latest version of NoID Privacy from GitHub.
    This script checks prerequisites, downloads the latest release, extracts it,
    and prepares it for execution.

.EXAMPLE
    # Download the bootstrap from an exact reviewed tag, inspect it, then run it.
    # Windows blocks downloaded scripts; Bypass applies to this process only.
    $installer = Join-Path $env:TEMP 'NoIDPrivacy-install-v2.2.5.ps1'
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/NexusOne23/noid-privacy/v2.2.5/install.ps1' -OutFile $installer -UseBasicParsing
    Get-Content -LiteralPath $installer
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $installer

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+, Windows 11, Admin Rights
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$InstallPath = "$env:USERPROFILE\NoIDPrivacy",

    [Parameter(Mandatory = $false)]
    [switch]$SkipAdminCheck
)

function Install-NoIDPrivacy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InstallPath = "$env:USERPROFILE\NoIDPrivacy",

        [Parameter(Mandatory = $false)]
        [switch]$SkipAdminCheck
    )

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Colors
$ColorSuccess = 'Green'
$ColorError = 'Red'
$ColorWarning = 'Yellow'
$ColorInfo = 'Cyan'

function Write-ColorOutput {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Color = 'White',

        [Parameter(Mandatory = $false)]
        [switch]$NoNewline
    )

    if ($NoNewline) {
        Write-Host $Message -ForegroundColor $Color -NoNewline
    }
    else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LatestRelease {
    try {
        Write-ColorOutput "Fetching latest release from GitHub..." -Color $ColorInfo
        $headers = @{ 'User-Agent' = 'NoID-Privacy-Installer' }
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/NexusOne23/noid-privacy/releases/latest" -UseBasicParsing -Headers $headers -ErrorAction Stop
        if (-not $release -or [string]::IsNullOrWhiteSpace([string]$release.tag_name)) {
            throw 'GitHub returned no complete latest-release record'
        }
        return $release
    }
    catch {
        throw "Unable to resolve a verified tagged release: $($_.Exception.Message)"
    }
}

function ConvertTo-ChecksumManifestText {
    <#
    .SYNOPSIS
        Decode a checksum-manifest web response into text.

    .DESCRIPTION
        GitHub serves release assets as application/octet-stream, so Windows
        PowerShell 5.1 exposes the response body as raw bytes instead of text.
        Casting that byte array to a string yields space-separated decimal
        numbers, which can never match a checksum line and would fail every
        installation with "found 0". Decode the bytes explicitly, accept an
        already-decoded string unchanged, and drop a leading UTF-8 BOM.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $ResponseContent
    )

    if ($ResponseContent -is [byte[]]) {
        if ($ResponseContent.Length -gt 1MB) {
            throw 'Checksum manifest exceeds the 1 MiB processing bound'
        }
        $manifestText = [System.Text.Encoding]::UTF8.GetString($ResponseContent)
    }
    else {
        $manifestText = [string]$ResponseContent
    }

    return $manifestText.TrimStart([char]0xFEFF)
}

function Test-DownloadChecksum {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$FilePath,
        [Parameter(Mandatory = $true)] [string]$ChecksumUrl,
        [Parameter(Mandatory = $true)] [string]$ExpectedRelativePath
    )

    try {
        $headers = @{ 'User-Agent' = 'NoID-Privacy-Installer' }
        $checksumResponse = Invoke-WebRequest -Uri $ChecksumUrl -UseBasicParsing -Headers $headers -ErrorAction Stop
        $checksumContent = ConvertTo-ChecksumManifestText -ResponseContent $checksumResponse.Content
        if ([string]::IsNullOrWhiteSpace($checksumContent) -or $checksumContent.Length -gt 1MB) {
            throw 'Checksum manifest is empty or exceeds the 1 MiB processing bound'
        }
    }
    catch {
        Write-ColorOutput "ERROR: Failed to download checksum manifest: $($_.Exception.Message)" -Color $ColorError
        return $false
    }

    $matchingHashes = @()
    foreach ($line in ($checksumContent -split "`r?`n")) {
        if ($line -match '^\s*([a-fA-F0-9]{64})\s+\*?(.+?)\s*$') {
            $hashCandidate = $matches[1].ToLowerInvariant()
            $fileCandidate = ([string]$matches[2]).Trim().Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($fileCandidate) -or
                [System.IO.Path]::IsPathRooted($fileCandidate) -or
                $fileCandidate -match '(^|/)\.\.(/|$)' -or
                $fileCandidate -match '[\r\n]') {
                Write-ColorOutput "ERROR: Checksum manifest contains an unsafe path: '$fileCandidate'." -Color $ColorError
                return $false
            }
            if ($fileCandidate -ceq $ExpectedRelativePath) {
                $matchingHashes += $hashCandidate
            }
        }
    }

    if ($matchingHashes.Count -ne 1) {
        Write-ColorOutput "ERROR: Expected exactly one checksum for '$ExpectedRelativePath', found $($matchingHashes.Count)." -Color $ColorError
        return $false
    }
    $expectedHash = $matchingHashes[0]

    $actualHash = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        Write-ColorOutput "ERROR: SHA256 mismatch -- possible tampering or corrupted download." -Color $ColorError
        Write-ColorOutput "  Expected: $expectedHash" -Color $ColorError
        Write-ColorOutput "  Actual:   $actualHash" -Color $ColorError
        return $false
    }
    Write-ColorOutput "SHA256 verified: $actualHash" -Color $ColorSuccess
    return $true
}

function Test-SafeInstallPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $resolvedPath = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        if ($resolvedPath.Provider.Name -ne 'FileSystem') {
            Write-ColorOutput "ERROR: Installation path '$Path' is not a file-system path." -Color $ColorError
            return $false
        }
        $fullPath = $resolvedPath.Path
    }
    catch {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
    }

    $normalized = $fullPath.TrimEnd('\').ToLowerInvariant()

    # Block drive roots (e.g. C:\)
    if ($normalized -match '^[a-z]:$') {
        Write-ColorOutput "ERROR: Installation path '$fullPath' is a drive root and is not allowed." -Color $ColorError
        return $false
    }

    # Block critical SYSTEM directories AND their subdirectories
    $blockedSystem = @()
    if ($env:WINDIR) { $blockedSystem += $env:WINDIR.TrimEnd('\').ToLowerInvariant() }
    if ($env:ProgramFiles) { $blockedSystem += $env:ProgramFiles.TrimEnd('\').ToLowerInvariant() }
    if (${env:ProgramFiles(x86)}) { $blockedSystem += ${env:ProgramFiles(x86)}.TrimEnd('\').ToLowerInvariant() }
    if ($env:SystemRoot) { $blockedSystem += $env:SystemRoot.TrimEnd('\').ToLowerInvariant() }

    foreach ($b in $blockedSystem) {
        if ([string]::IsNullOrEmpty($b)) { continue }
        if ($normalized -eq $b -or $normalized.StartsWith($b + '\')) {
            Write-ColorOutput "ERROR: Installation path '$fullPath' is too close to a critical system directory ($b)." -Color $ColorError
            return $false
        }
    }

    # Block the user-profile ROOT exactly (subdirectories like $env:USERPROFILE\NoIDPrivacy are allowed)
    if ($env:USERPROFILE) {
        $userProfileRoot = $env:USERPROFILE.TrimEnd('\').ToLowerInvariant()
        if ($normalized -eq $userProfileRoot) {
            Write-ColorOutput "ERROR: Installation path '$fullPath' equals the user profile root (use a subdirectory)." -Color $ColorError
            return $false
        }

        $usersRoot = (Split-Path $env:USERPROFILE -Parent).TrimEnd('\').ToLowerInvariant()
        if ($normalized -eq $usersRoot -or
            ($normalized.StartsWith($usersRoot + '\') -and -not $normalized.StartsWith($userProfileRoot + '\'))) {
            Write-ColorOutput "ERROR: Installation path '$fullPath' targets the users root or another user profile." -Color $ColorError
            return $false
        }
    }

    # These shared/special roots may contain unrelated system or application
    # state. Their exact root must never become the transaction replacement.
    $blockedExactRoots = @()
    foreach ($candidate in @($env:ProgramData, $env:PUBLIC, $env:TEMP, $env:TMP)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
            $blockedExactRoots += [System.IO.Path]::GetFullPath([string]$candidate).TrimEnd('\').ToLowerInvariant()
        }
    }
    if ($env:SystemDrive) {
        foreach ($relativeRoot in @('Recovery', 'PerfLogs', 'System Volume Information', '$Recycle.Bin', 'Documents and Settings')) {
            $blockedExactRoots += (Join-Path $env:SystemDrive $relativeRoot).TrimEnd('\').ToLowerInvariant()
        }
    }
    if ($normalized -in @($blockedExactRoots | Select-Object -Unique)) {
        Write-ColorOutput "ERROR: Installation path '$fullPath' is a protected shared/system root." -Color $ColorError
        return $false
    }

    # A junction/symlink in an existing ancestor would invalidate the critical-path
    # checks above and could redirect staging, replacement or cleanup elsewhere.
    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    $relativePart = $fullPath.Substring($pathRoot.Length)
    $currentPath = $pathRoot
    foreach ($component in @($relativePart -split '[\\/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $currentPath = Join-Path $currentPath $component
        if (-not (Test-Path -LiteralPath $currentPath)) {
            break
        }
        $existingItem = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
        if (($existingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Write-ColorOutput "ERROR: Installation path traverses a reparse point: '$currentPath'." -Color $ColorError
            return $false
        }
    }

    if ((Test-Path -LiteralPath $fullPath) -and -not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        Write-ColorOutput "ERROR: Existing installation path is not a directory: '$fullPath'." -Color $ColorError
        return $false
    }

    return $true
}

function Assert-SafeReleaseArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArchivePath
    )

    # These bounds are intentionally far above the current release payload while
    # still preventing a checksum-valid release archive from exhausting the host.
    $maxArchiveBytes = 128MB
    $maxEntryBytes = 64MB
    $maxExpandedBytes = 512MB
    $maxEntryCount = 10000

    $archiveItem = Get-Item -LiteralPath $ArchivePath -Force -ErrorAction Stop
    if ($archiveItem.PSIsContainer -or $archiveItem.Length -le 0 -or $archiveItem.Length -gt $maxArchiveBytes) {
        throw "Release archive size is outside the supported 1-$maxArchiveBytes byte range"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $archive = [System.IO.Compression.ZipFile]::OpenRead($archiveItem.FullName)
    try {
        $entries = @($archive.Entries)
        if ($entries.Count -eq 0 -or $entries.Count -gt $maxEntryCount) {
            throw "Release archive entry count '$($entries.Count)' is outside the supported 1-$maxEntryCount range"
        }

        $seenPaths = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $entryKinds = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        [long]$expandedBytes = 0

        foreach ($entry in $entries) {
            $rawPath = [string]$entry.FullName
            if ([string]::IsNullOrWhiteSpace($rawPath) -or
                $rawPath.StartsWith('/') -or $rawPath.StartsWith('\') -or
                [System.IO.Path]::IsPathRooted($rawPath) -or $rawPath -match ':') {
                throw "Release archive contains an unsafe rooted/ADS path: '$rawPath'"
            }

            $isDirectory = $rawPath.EndsWith('/') -or $rawPath.EndsWith('\') -or [string]::IsNullOrEmpty([string]$entry.Name)
            $trimmedPath = $rawPath.TrimEnd('/', '\')
            $segments = @($trimmedPath -split '[\\/]')
            if ($segments.Count -eq 0 -or @($segments | Where-Object { [string]::IsNullOrEmpty($_) }).Count -gt 0) {
                throw "Release archive contains an empty path segment: '$rawPath'"
            }
            foreach ($segment in $segments) {
                if ($segment -eq '.' -or $segment -eq '..' -or
                    $segment -match '[\x00-\x1f<>"|?*]' -or $segment -match '[\. ]$' -or
                    $segment -match '(?i)^(CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(?:\..*)?$') {
                    throw "Release archive contains a Windows-unsafe path segment '$segment' in '$rawPath'"
                }
            }

            $canonicalPath = $segments -join '/'
            if ($seenPaths.ContainsKey($canonicalPath)) {
                throw "Release archive contains a duplicate/case-colliding path '$rawPath' and '$($seenPaths[$canonicalPath])'"
            }
            $seenPaths.Add($canonicalPath, $rawPath)
            $entryKinds.Add($canonicalPath, $(if ($isDirectory) { 'Directory' } else { 'File' }))

            # Reject Unix symlinks and DOS reparse-point entries before extraction.
            $externalAttributes = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$entry.ExternalAttributes), 0)
            $unixFileType = (($externalAttributes -shr 16) -band 0xF000)
            if ($unixFileType -eq 0xA000 -or ($externalAttributes -band [uint32][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Release archive contains a link/reparse entry: '$rawPath'"
            }
            if ($unixFileType -notin @(0, 0x4000, 0x8000)) {
                throw "Release archive contains an unsupported Unix file type for '$rawPath'"
            }

            if ($entry.Length -lt 0 -or $entry.Length -gt $maxEntryBytes) {
                throw "Release archive entry '$rawPath' exceeds the supported size bound"
            }
            $expandedBytes += [long]$entry.Length
            if ($expandedBytes -gt $maxExpandedBytes) {
                throw "Release archive expanded size exceeds the supported $maxExpandedBytes-byte bound"
            }
        }

        foreach ($canonicalPath in @($entryKinds.Keys)) {
            $parts = @($canonicalPath -split '/')
            for ($index = 1; $index -lt $parts.Count; $index++) {
                $ancestor = $parts[0..($index - 1)] -join '/'
                if ($entryKinds.ContainsKey($ancestor) -and $entryKinds[$ancestor] -eq 'File') {
                    throw "Release archive path '$canonicalPath' descends through file entry '$ancestor'"
                }
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Assert-ReleaseAssetUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Url,
        [Parameter(Mandatory = $true)] [string]$Tag,
        [Parameter(Mandatory = $true)] [string]$AssetName
    )

    $expectedUrl = "https://github.com/NexusOne23/noid-privacy/releases/download/$Tag/$AssetName"
    [Uri]$candidateUri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$candidateUri) -or
        $candidateUri.Scheme -cne 'https' -or $candidateUri.Host -cne 'github.com' -or
        $candidateUri.UserInfo -or $candidateUri.Query -or $candidateUri.Fragment -or
        $candidateUri.AbsoluteUri -cne $expectedUrl) {
        throw "Release asset URL is not the exact expected GitHub URL for '$AssetName'"
    }
}

function Assert-ReleasePayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CandidateRoot,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedVersion
    )

    $candidateFullPath = [System.IO.Path]::GetFullPath($CandidateRoot).TrimEnd('\', '/')
    if (-not (Test-Path -LiteralPath $candidateFullPath -PathType Container)) {
        throw "Release payload root is missing: $candidateFullPath"
    }

    $requiredFiles = @('NoIDPrivacy.ps1', 'NoIDPrivacy-Interactive.ps1', 'Start-NoIDPrivacy.bat', 'VERSION', 'config.json')
    $requiredDirectories = @('Core', 'Modules', 'Tools')
    foreach ($requiredFile in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $candidateFullPath $requiredFile) -PathType Leaf)) {
            throw "Release payload is missing required file '$requiredFile'"
        }
    }
    foreach ($requiredDirectory in $requiredDirectories) {
        if (-not (Test-Path -LiteralPath (Join-Path $candidateFullPath $requiredDirectory) -PathType Container)) {
            throw "Release payload is missing required directory '$requiredDirectory'"
        }
    }

    foreach ($forbiddenRuntimeDirectory in @('Backups', 'Logs', 'Reports')) {
        if (Test-Path -LiteralPath (Join-Path $candidateFullPath $forbiddenRuntimeDirectory)) {
            throw "Release payload contains runtime directory '$forbiddenRuntimeDirectory'"
        }
    }

    $allItems = @(Get-ChildItem -LiteralPath $candidateFullPath -Force -Recurse -ErrorAction Stop)
    $reparseItems = @($allItems | Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 })
    if ($reparseItems.Count -gt 0) {
        throw "Release payload contains unsupported reparse points: $($reparseItems[0].FullName)"
    }

    $payloadVersion = (Get-Content -LiteralPath (Join-Path $candidateFullPath 'VERSION') -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
    if ($payloadVersion -notmatch '^\d+\.\d+\.\d+$' -or $payloadVersion -ne $ExpectedVersion) {
        throw "Release VERSION '$payloadVersion' does not match tag version '$ExpectedVersion'"
    }
    $runtimeConfig = Get-Content -LiteralPath (Join-Path $candidateFullPath 'config.json') -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([string]$runtimeConfig.version -ne $ExpectedVersion) {
        throw "config.json version '$($runtimeConfig.version)' does not match '$ExpectedVersion'"
    }

    $versionBoundFiles = @(
        [PSCustomObject]@{ Path = 'install.ps1'; Pattern = '(?m)^\s*Version:\s*{0}\s*$' -f [regex]::Escape($ExpectedVersion) }
        [PSCustomObject]@{ Path = 'NoIDPrivacy.ps1'; Pattern = '(?m)^\s*Version:\s*{0}\s*$' -f [regex]::Escape($ExpectedVersion) }
        [PSCustomObject]@{ Path = 'NoIDPrivacy-Interactive.ps1'; Pattern = '(?m)^\s*Version:\s*{0}\s*$' -f [regex]::Escape($ExpectedVersion) }
        [PSCustomObject]@{ Path = 'Start-NoIDPrivacy.bat'; Pattern = '(?m)^REM Version:\s*{0}\s*$' -f [regex]::Escape($ExpectedVersion) }
        [PSCustomObject]@{ Path = 'Modules\_ModuleTemplate\ModuleTemplate.psm1'; Pattern = '\$script:ModuleVersion\s*=\s*["'']{0}["'']' -f [regex]::Escape($ExpectedVersion) }
    )
    foreach ($versionBoundFile in $versionBoundFiles) {
        $versionBoundPath = Join-Path $candidateFullPath ([string]$versionBoundFile.Path)
        if (-not (Test-Path -LiteralPath $versionBoundPath -PathType Leaf)) {
            throw "Release payload is missing version-bound file '$($versionBoundFile.Path)'"
        }
        $versionBoundContent = Get-Content -LiteralPath $versionBoundPath -Raw -Encoding UTF8 -ErrorAction Stop
        if ($versionBoundContent -notmatch [string]$versionBoundFile.Pattern) {
            throw "Version marker in '$($versionBoundFile.Path)' does not match '$ExpectedVersion'"
        }
    }

    $templateManifestPath = Join-Path $candidateFullPath 'Modules\_ModuleTemplate\ModuleTemplate.psd1'
    $templateManifest = Import-PowerShellDataFile -Path $templateManifestPath -ErrorAction Stop
    if ([string]$templateManifest.ModuleVersion -ne $ExpectedVersion) {
        throw "Module template manifest version '$($templateManifest.ModuleVersion)' does not match '$ExpectedVersion'"
    }

    $productionModules = @('SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI', 'EdgeHardening', 'AdvancedSecurity')
    foreach ($moduleName in $productionModules) {
        $manifestPath = Join-Path $candidateFullPath "Modules\$moduleName\$moduleName.psd1"
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "Release payload is missing module manifest '$moduleName.psd1'"
        }
        $manifest = Import-PowerShellDataFile -Path $manifestPath -ErrorAction Stop
        if ([string]$manifest.ModuleVersion -ne $ExpectedVersion) {
            throw "Module '$moduleName' version '$($manifest.ModuleVersion)' does not match '$ExpectedVersion'"
        }
    }

    $parseTargets = @($allItems | Where-Object { -not $_.PSIsContainer -and $_.Extension -in @('.ps1', '.psm1', '.psd1') })
    foreach ($parseTarget in $parseTargets) {
        $tokens = $null
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($parseTarget.FullName, [ref]$tokens, [ref]$parseErrors)
        if (@($parseErrors).Count -gt 0) {
            throw "PowerShell parse failure in '$($parseTarget.FullName)': $($parseErrors[0].Message)"
        }
    }

    foreach ($jsonFile in @($allItems | Where-Object { -not $_.PSIsContainer -and $_.Extension -eq '.json' })) {
        $null = Get-Content -LiteralPath $jsonFile.FullName -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    }
}

# Banner
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "        NoID Privacy - Release Installer                  " -ForegroundColor Cyan
Write-Host "   Professional Windows 11 Security & Privacy Hardening Framework   " -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Administrator
if (-not $SkipAdminCheck) {
    Write-ColorOutput "Checking administrator privileges..." -Color $ColorInfo
    if (-not (Test-Administrator)) {
        Write-ColorOutput "ERROR: Administrator rights required!" -Color $ColorError
        Write-ColorOutput "   Please run PowerShell as Administrator and try again." -Color $ColorWarning
        Write-ColorOutput @"

To run as Administrator:
1. Press Win + X
2. Click "Terminal (Admin)" or "PowerShell (Admin)"
3. Run the install command again

"@ -Color $ColorInfo
        exit 1
    }
    Write-ColorOutput "Administrator privileges confirmed" -Color $ColorSuccess
}

# Step 2: Check PowerShell Version
Write-ColorOutput "Checking PowerShell version..." -Color $ColorInfo
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
    Write-ColorOutput "ERROR: PowerShell 5.1 or higher required!" -Color $ColorError
    Write-ColorOutput "   Current version: $($psVersion.ToString())" -Color $ColorWarning
    exit 1
}
Write-ColorOutput "PowerShell version OK ($($psVersion.ToString()))" -Color $ColorSuccess

# Step 3: Check native processor architecture
Write-ColorOutput "Checking processor architecture..." -Color $ColorInfo
$processorArchitectures = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | ForEach-Object {
        if ($null -eq $_.Architecture) {
            throw 'Win32_Processor did not report Architecture for every processor'
        }
        [int]$_.Architecture
    } | Sort-Object -Unique)
if ($processorArchitectures.Count -ne 1 -or [int]$processorArchitectures[0] -ne 9) {
    $detectedArchitecture = if ($processorArchitectures.Count -eq 1 -and [int]$processorArchitectures[0] -eq 12) { 'ARM64' } else { $processorArchitectures -join ',' }
    Write-ColorOutput "ERROR: NoID Privacy supports Windows 11 x64 (AMD64/x86-64) only." -Color $ColorError
    Write-ColorOutput "   Windows on Arm (ARM64) and other processor architectures are not supported. Detected: $detectedArchitecture" -Color $ColorWarning
    exit 1
}
Write-ColorOutput "Processor architecture OK (x64/AMD64)" -Color $ColorSuccess

# Step 4: Check Windows Version
Write-ColorOutput "Checking Windows version..." -Color $ColorInfo
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$currentVersionKey = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
$buildNumber = [int]$currentVersionKey.GetValue('CurrentBuildNumber', $osInfo.BuildNumber)
$displayVersion = [string]$currentVersionKey.GetValue('DisplayVersion', '')
$installationType = [string]$currentVersionKey.GetValue('InstallationType', '')
$isClient = ([int]$osInfo.ProductType -eq 1 -and $installationType -notmatch '(?i)Server')
$osVersion = $null
$supportLevel = 'Unsupported'
$supportReason = 'This Windows build family is not supported'

if (-not $isClient) {
    $supportReason = 'Windows Server and domain-controller SKUs are not supported'
}
elseif ($displayVersion -eq '24H2' -and $buildNumber -ge 26100 -and $buildNumber -lt 26200) {
    $osVersion = '24H2'
    $supportLevel = 'Stable'
}
elseif ($displayVersion -eq '25H2' -and $buildNumber -ge 26200 -and $buildNumber -lt 26300) {
    $osVersion = '25H2'
    $supportLevel = 'Stable'
}
elseif ($displayVersion -eq '26H2' -and $buildNumber -ge 26300 -and $buildNumber -lt 28000) {
    $osVersion = '26H2'
    $supportLevel = 'Experimental'
}
elseif ($displayVersion -eq '26H1' -or ($buildNumber -ge 28000 -and $buildNumber -lt 29000)) {
    $supportReason = 'Windows 11 26H1 uses a different core and is not a supported 26H2 upgrade target'
}
elseif ($buildNumber -ge 29600) {
    $supportReason = 'Future-platform/Canary builds are outside the explicitly recognized 26H2 Experimental Preview boundary'
}
elseif ([string]::IsNullOrWhiteSpace($displayVersion)) {
    if ($buildNumber -ge 26100 -and $buildNumber -lt 26200) {
        $osVersion = '24H2'
        $supportLevel = 'Stable'
    }
    elseif ($buildNumber -ge 26200 -and $buildNumber -lt 26300) {
        $osVersion = '25H2'
        $supportLevel = 'Stable'
    }
    elseif ($buildNumber -ge 26300 -and $buildNumber -lt 28000) {
        $supportReason = 'Build 26300-27999 is accepted only when Windows explicitly reports the official 26H2 DisplayVersion'
    }
}

if ($supportLevel -eq 'Unsupported') {
    Write-ColorOutput "ERROR: A supported Windows 11 client release is required." -Color $ColorError
    Write-ColorOutput "   Detected: DisplayVersion='$displayVersion', Build=$buildNumber, ProductType=$($osInfo.ProductType)" -Color $ColorWarning
    Write-ColorOutput "   Reason: $supportReason" -Color $ColorWarning
    exit 1
}

Write-ColorOutput "Windows 11 $osVersion detected (Build $buildNumber)" -Color $ColorSuccess
if ($supportLevel -eq 'Experimental') {
    Write-ColorOutput 'WARNING: Windows 11 26H2 is recognized only as an Experimental Preview; it is currently not runtime-validated or release-approved. Preview policies and behavior can change.' -Color $ColorWarning
}

# Step 5: Validate destination without modifying an existing installation
Write-ColorOutput "Validating installation destination..." -Color $ColorInfo
if (-not (Test-SafeInstallPath -Path $InstallPath)) {
    Write-ColorOutput "Installation aborted due to unsafe install path." -Color $ColorError
    exit 1
}
$fullInstallPath = [System.IO.Path]::GetFullPath($InstallPath).TrimEnd('\')
$installParent = Split-Path $fullInstallPath -Parent
$replaceExisting = Test-Path -LiteralPath $fullInstallPath
if ($replaceExisting) {
    Write-ColorOutput "Directory already exists: $fullInstallPath" -Color $ColorWarning
    Write-Host ""
    Write-ColorOutput "   [N] NO - Cancel the installation (default)" -Color Green
    Write-ColorOutput "       - The existing installation is left untouched" -Color Gray
    Write-Host ""
    Write-ColorOutput "   [Y] YES - Overwrite the existing installation" -Color Cyan
    Write-ColorOutput "       - Program files are replaced; Backups, Logs and Reports are retained" -Color Gray
    Write-Host ""

    do {
        Write-ColorOutput "   Overwrite existing installation? [Y/N] (default: N): " -Color Yellow -NoNewline
        $response = Read-Host
        if ([string]::IsNullOrWhiteSpace($response)) { $response = 'N' }
        $response = $response.Trim().ToUpperInvariant()

        if ($response -notin @('Y', 'N')) {
            Write-Host ""
            Write-ColorOutput "   Invalid input. Please enter Y or N." -Color Red
            Write-Host ""
        }
    } while ($response -notin @('Y', 'N'))

    if ($response -ne 'Y') {
        Write-ColorOutput "Installation cancelled by user" -Color $ColorWarning
        exit 0
    }
}
if (-not (Test-Path -LiteralPath $installParent)) {
    New-Item -ItemType Directory -Path $installParent -Force | Out-Null
}

# Step 5: Download Latest Release or Main Branch
$downloadUrl = $null
$checksumUrl = $null
$zipAssetName = $null
$operationId = [Guid]::NewGuid().ToString('N')
$downloadPath = Join-Path $env:TEMP "NoIDPrivacy-$operationId.zip"
$stagingPath = Join-Path $installParent ".NoIDPrivacy-staging-$operationId"
$previousPath = Join-Path $installParent ".NoIDPrivacy-previous-$operationId"
$retainedRuntimeDirectories = @('Backups', 'Logs', 'Reports')
$movedRuntimeDirectories = [System.Collections.Generic.List[string]]::new()

$release = $null
try {
    $release = Get-LatestRelease
}
catch {
    Write-ColorOutput "ERROR: $($_.Exception.Message)" -Color $ColorError
    Write-ColorOutput 'The installer accepts checksum-verified tagged releases only.' -Color $ColorWarning
    exit 1
}

if ([string]$release.tag_name -cnotmatch '^v(\d+\.\d+\.\d+)$') {
    Write-ColorOutput "ERROR: Release tag '$($release.tag_name)' is not in v<MAJOR>.<MINOR>.<PATCH> form." -Color $ColorError
    exit 1
}
$expectedVersion = $Matches[1]
Write-ColorOutput "Latest release: $($release.tag_name)" -Color $ColorInfo
$expectedAssetName = "NoIDPrivacy-$($release.tag_name).zip"
$zipAsset = @($release.assets | Where-Object { $_.name -ceq $expectedAssetName })
$checksumAssets = @($release.assets | Where-Object { $_.name -ceq 'CHECKSUMS.sha256' })

if ($zipAsset.Count -ne 1) {
    Write-ColorOutput "ERROR: Release must contain exactly one '$expectedAssetName' asset." -Color $ColorError
    exit 1
}
if ($checksumAssets.Count -ne 1) {
    Write-ColorOutput "ERROR: Release must contain exactly one 'CHECKSUMS.sha256' asset; found $($checksumAssets.Count)." -Color $ColorError
    exit 1
}
if ([long]$zipAsset[0].size -le 0 -or [long]$zipAsset[0].size -gt 128MB) {
    Write-ColorOutput "ERROR: Release ZIP metadata is outside the supported 1-128 MiB bound." -Color $ColorError
    exit 1
}
if ([long]$checksumAssets[0].size -le 0 -or [long]$checksumAssets[0].size -gt 1MB) {
    Write-ColorOutput "ERROR: Checksum asset metadata is outside the supported 1-byte-to-1-MiB bound." -Color $ColorError
    exit 1
}

$downloadUrl = [string]$zipAsset[0].browser_download_url
$zipAssetName = [string]$zipAsset[0].name
$checksumUrl = [string]$checksumAssets[0].browser_download_url
if ([string]::IsNullOrWhiteSpace($downloadUrl) -or [string]::IsNullOrWhiteSpace($checksumUrl)) {
    Write-ColorOutput 'ERROR: Release assets do not expose complete download URLs.' -Color $ColorError
    exit 1
}
try {
    Assert-ReleaseAssetUrl -Url $downloadUrl -Tag ([string]$release.tag_name) -AssetName $zipAssetName
    Assert-ReleaseAssetUrl -Url $checksumUrl -Tag ([string]$release.tag_name) -AssetName 'CHECKSUMS.sha256'
}
catch {
    Write-ColorOutput "ERROR: $($_.Exception.Message)" -Color $ColorError
    exit 1
}
Write-ColorOutput "Downloading release: $zipAssetName" -Color $ColorInfo

$previousMoved = $false
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -UseBasicParsing -ErrorAction Stop
    Write-ColorOutput "Download complete" -Color $ColorSuccess

    Write-ColorOutput "Verifying SHA256 checksum..." -Color $ColorInfo
    if (-not (Test-DownloadChecksum -FilePath $downloadPath -ChecksumUrl $checksumUrl -ExpectedRelativePath $zipAssetName)) {
        throw "Release checksum verification failed"
    }

    Write-ColorOutput "Validating archive paths, types and resource bounds..." -Color $ColorInfo
    Assert-SafeReleaseArchive -ArchivePath $downloadPath

    Write-ColorOutput "Extracting files to staging..." -Color $ColorInfo
    if ((Test-Path -LiteralPath $stagingPath) -or (Test-Path -LiteralPath $previousPath)) {
        throw 'Per-operation staging or rollback path unexpectedly already exists'
    }
    New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null
    Expand-Archive -LiteralPath $downloadPath -DestinationPath $stagingPath -Force -ErrorAction Stop

    $topLevelFiles = @(Get-ChildItem -LiteralPath $stagingPath -File -Force)
    $topLevelDirectories = @(Get-ChildItem -LiteralPath $stagingPath -Directory -Force)
    $candidateRoot = if ($topLevelFiles.Count -eq 0 -and $topLevelDirectories.Count -eq 1) {
        $topLevelDirectories[0].FullName
    }
    else {
        $stagingPath
    }

    Write-ColorOutput "Validating staged release payload..." -Color $ColorInfo
    Assert-ReleasePayload -CandidateRoot $candidateRoot -ExpectedVersion $expectedVersion
    foreach ($scriptFile in @(Get-ChildItem -LiteralPath $candidateRoot -Recurse -File -Force -ErrorAction Stop |
            Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1') })) {
        Unblock-File -LiteralPath $scriptFile.FullName -ErrorAction Stop
    }

    if ($replaceExisting) {
        Write-ColorOutput "Moving existing installation to rollback location..." -Color $ColorInfo
        Move-Item -LiteralPath $fullInstallPath -Destination $previousPath -ErrorAction Stop
        $previousMoved = $true
    }

    Move-Item -LiteralPath $candidateRoot -Destination $fullInstallPath -ErrorAction Stop
    Assert-ReleasePayload -CandidateRoot $fullInstallPath -ExpectedVersion $expectedVersion

    # Runtime records belong to the user, not to a release payload. Move each
    # complete directory into the validated new installation before removing any
    # old program files. In particular, BAVR sessions have no retention deadline.
    if ($previousMoved) {
        foreach ($runtimeDirectoryName in $retainedRuntimeDirectories) {
            $previousRuntimePath = Join-Path $previousPath $runtimeDirectoryName
            if (-not (Test-Path -LiteralPath $previousRuntimePath)) {
                continue
            }
            if (-not (Test-Path -LiteralPath $previousRuntimePath -PathType Container)) {
                throw "Retained runtime path is not a directory: $previousRuntimePath"
            }
            $newRuntimePath = Join-Path $fullInstallPath $runtimeDirectoryName
            if (Test-Path -LiteralPath $newRuntimePath) {
                throw "Validated release unexpectedly collides with retained runtime directory: $newRuntimePath"
            }

            Move-Item -LiteralPath $previousRuntimePath -Destination $newRuntimePath -ErrorAction Stop
            $movedRuntimeDirectories.Add($runtimeDirectoryName)
            if ((Test-Path -LiteralPath $previousRuntimePath) -or
                -not (Test-Path -LiteralPath $newRuntimePath -PathType Container)) {
                throw "Retained runtime directory move did not complete: $runtimeDirectoryName"
            }
            Write-ColorOutput "Retained indefinitely: $newRuntimePath" -Color $ColorSuccess
        }
    }

    if (Test-Path -LiteralPath $previousPath) {
        try {
            Remove-Item -LiteralPath $previousPath -Recurse -Force -ErrorAction Stop
        }
        catch {
            # The new installation and every retained runtime directory are
            # already complete. Obsolete program-file cleanup must not turn a
            # successful, data-preserving upgrade into a destructive rollback.
            Write-ColorOutput "WARNING: Obsolete previous program files remain at '$previousPath': $($_.Exception.Message)" -Color $ColorWarning
        }
        $previousMoved = $false
    }
    Write-ColorOutput "Files installed successfully" -Color $ColorSuccess
}
catch {
    $installationError = $_.Exception.Message
    $rollbackErrors = [System.Collections.Generic.List[string]]::new()
    $retainedDataRollbackFailed = $false

    # If runtime directories were already moved into the new installation,
    # return them before removing that installation. A failed return is a hard
    # stop: leave both transaction directories in place and never delete data.
    if ($previousMoved -and
        (Test-Path -LiteralPath $previousPath -PathType Container) -and
        (Test-Path -LiteralPath $fullInstallPath -PathType Container)) {
        for ($runtimeIndex = $movedRuntimeDirectories.Count - 1; $runtimeIndex -ge 0; $runtimeIndex--) {
            $runtimeDirectoryName = $movedRuntimeDirectories[$runtimeIndex]
            $newRuntimePath = Join-Path $fullInstallPath $runtimeDirectoryName
            $previousRuntimePath = Join-Path $previousPath $runtimeDirectoryName
            try {
                if (-not (Test-Path -LiteralPath $newRuntimePath -PathType Container)) {
                    throw "Moved runtime directory is missing: $newRuntimePath"
                }
                if (Test-Path -LiteralPath $previousRuntimePath) {
                    throw "Rollback destination already exists: $previousRuntimePath"
                }
                Move-Item -LiteralPath $newRuntimePath -Destination $previousRuntimePath -ErrorAction Stop
                if ((Test-Path -LiteralPath $newRuntimePath) -or
                    -not (Test-Path -LiteralPath $previousRuntimePath -PathType Container)) {
                    throw "Runtime rollback move did not complete: $runtimeDirectoryName"
                }
            }
            catch {
                $retainedDataRollbackFailed = $true
                $rollbackErrors.Add("Retained runtime directory was not moved back safely ($runtimeDirectoryName): $($_.Exception.Message)")
            }
        }
    }

    if (-not $retainedDataRollbackFailed -and
        ($previousMoved -or -not $replaceExisting) -and
        (Test-Path -LiteralPath $fullInstallPath)) {
        try {
            Remove-Item -LiteralPath $fullInstallPath -Recurse -Force -ErrorAction Stop
        }
        catch {
            $rollbackErrors.Add("Failed to remove incomplete new installation: $($_.Exception.Message)")
        }
    }
    if ($previousMoved -and -not $retainedDataRollbackFailed) {
        if (-not (Test-Path -LiteralPath $previousPath -PathType Container)) {
            $rollbackErrors.Add("Rollback directory is missing: $previousPath")
        }
        elseif (-not (Test-Path -LiteralPath $fullInstallPath)) {
            try {
                Move-Item -LiteralPath $previousPath -Destination $fullInstallPath -ErrorAction Stop
                $previousMoved = $false
            }
            catch {
                $rollbackErrors.Add("Failed to restore previous installation: $($_.Exception.Message)")
            }
        }
    }

    if ($rollbackErrors.Count -eq 0) {
        if ($replaceExisting) {
            Write-ColorOutput "ERROR: Installation failed; the previous installation was preserved/restored." -Color $ColorError
        }
        else {
            Write-ColorOutput "ERROR: Installation failed; no existing installation was replaced." -Color $ColorError
        }
    }
    else {
        Write-ColorOutput "CRITICAL: Installation failed and automatic rollback was incomplete." -Color $ColorError
        foreach ($rollbackError in $rollbackErrors) {
            Write-ColorOutput "   $rollbackError" -Color $ColorError
        }
        if (Test-Path -LiteralPath $previousPath) {
            Write-ColorOutput "   Previous installation remains at: $previousPath" -Color $ColorWarning
        }
        if (Test-Path -LiteralPath $fullInstallPath) {
            Write-ColorOutput "   New transaction directory remains at: $fullInstallPath" -Color $ColorWarning
        }
    }
    Write-ColorOutput "   Original failure: $installationError" -Color $ColorWarning
    exit 1
}
finally {
    foreach ($temporaryPath in @($downloadPath, $stagingPath)) {
        try {
            if (Test-Path -LiteralPath $temporaryPath) {
                Remove-Item -LiteralPath $temporaryPath -Recurse -Force -ErrorAction Stop
            }
        }
        catch {
            Write-ColorOutput "WARNING: Temporary path could not be removed: $temporaryPath" -Color $ColorWarning
        }
    }
}

$InstallPath = $fullInstallPath

# Step 8: Display Success Message
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Green
Write-Host "                 INSTALLATION COMPLETE!                        " -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Installation Path: $InstallPath" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Green
Write-Host ""
Write-Host "1. Review the documentation:" -ForegroundColor Green
Write-Host "   README: $InstallPath\README.md" -ForegroundColor Green
Write-Host ""
Write-Host "2. Create a system backup (CRITICAL!):" -ForegroundColor Green
Write-Host "   - System Restore Point" -ForegroundColor Green
Write-Host "   - Full system image" -ForegroundColor Green
Write-Host "   - VM snapshot (if applicable)" -ForegroundColor Green
Write-Host ""
Write-Host "3. Run the interactive setup:" -ForegroundColor Green
Write-Host "   cd `"$InstallPath`"" -ForegroundColor Green
Write-Host "   .\Start-NoIDPrivacy.bat" -ForegroundColor Green
Write-Host ""
Write-Host "4. Or run directly with PowerShell:" -ForegroundColor Green
Write-Host "   cd `"$InstallPath`"" -ForegroundColor Green
Write-Host "   .\NoIDPrivacy.ps1 -Module All" -ForegroundColor Green
Write-Host ""
Write-Host "5. After execution, verify settings:" -ForegroundColor Green
Write-Host "   .\Tools\Verify-Complete-Hardening.ps1" -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT WARNINGS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "- This tool modifies CRITICAL system settings" -ForegroundColor Yellow
Write-Host "- BACKUP your system BEFORE running" -ForegroundColor Yellow
Write-Host "- Test in a VM first (recommended)" -ForegroundColor Yellow
Write-Host "- Domain-joined systems: Coordinate with IT" -ForegroundColor Yellow
Write-Host "- Read SECURITY.md for security considerations" -ForegroundColor Yellow
Write-Host ""
Write-Host "Documentation:" -ForegroundColor Cyan
Write-Host "- README.md - Complete guide" -ForegroundColor Cyan
Write-Host "- CHANGELOG.md - Version history" -ForegroundColor Cyan
Write-Host "- SECURITY.md - Security policy" -ForegroundColor Cyan
Write-Host "- LICENSE - GPL v3.0 dual-license" -ForegroundColor Cyan
Write-Host ""
Write-Host "Community & Support:" -ForegroundColor Cyan
Write-Host "- GitHub Issues: https://github.com/NexusOne23/noid-privacy/issues" -ForegroundColor Cyan
Write-Host "- Discussions: https://github.com/NexusOne23/noid-privacy/discussions" -ForegroundColor Cyan

Write-Host ""
Write-ColorOutput "Press any key to start interactive menu..." -Color White -NoNewline
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# Auto-start interactive menu after user confirmation
Write-ColorOutput "Starting NoID Privacy..." -Color $ColorInfo

try {
    $locationPushed = $false
    Push-Location $InstallPath
    $locationPushed = $true
    & .\Start-NoIDPrivacy.bat
}
catch {
    Write-ColorOutput "Could not auto-start. Please run manually:" -Color $ColorWarning
    Write-ColorOutput "   cd `"$InstallPath`"" -Color $ColorInfo
    Write-ColorOutput "   .\Start-NoIDPrivacy.bat" -Color $ColorInfo
}
finally {
    if ($locationPushed) {
        Pop-Location
    }
}

Write-Host ""
Write-ColorOutput "NoID Privacy - Keeping Windows 11 secure and private!" -Color $ColorSuccess
}

# Call the function
Install-NoIDPrivacy @PSBoundParameters
