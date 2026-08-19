#Requires -Version 5.1

function Get-EdgeInstallationStatus {
    <#
.SYNOPSIS
        Resolve machine-wide and interactive-user Microsoft Edge executables.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $candidates = [System.Collections.Generic.List[string]]::new()
    $appPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe'
    if (Test-Path -LiteralPath $appPath -PathType Container -ErrorAction Stop) {
        $key = Get-Item -LiteralPath $appPath -ErrorAction Stop
        $defaultPath = [string]$key.GetValue('', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if (-not [string]::IsNullOrWhiteSpace($defaultPath)) { $candidates.Add($defaultPath) }
    }
    foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if (-not [string]::IsNullOrWhiteSpace($root)) {
            $candidates.Add((Join-Path $root 'Microsoft\Edge\Application\msedge.exe'))
        }
    }
    # Machine policy affects every local profile. Enumerate ProfileList rather
    # than coupling a machine-policy operation to a currently running Explorer
    # process; this also detects logged-out per-user Edge installations.
    $profileListRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    if (Test-Path -LiteralPath $profileListRoot -PathType Container -ErrorAction Stop) {
        foreach ($profileKey in @(Get-ChildItem -LiteralPath $profileListRoot -ErrorAction Stop)) {
            $profileSid = [string]$profileKey.PSChildName
            if ($profileSid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$') { continue }
            $profilePathRaw = [string]$profileKey.GetValue(
                'ProfileImagePath', $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            if (-not [string]::IsNullOrWhiteSpace($profilePathRaw)) {
                $profilePath = [Environment]::ExpandEnvironmentVariables($profilePathRaw)
                $candidates.Add((Join-Path $profilePath 'AppData\Local\Microsoft\Edge\Application\msedge.exe'))
            }
            $userAppPath = "Registry::HKEY_USERS\$profileSid\Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"
            if (Test-Path -LiteralPath $userAppPath -PathType Container -ErrorAction Stop) {
                $userAppKey = Get-Item -LiteralPath $userAppPath -ErrorAction Stop
                $userDefaultPath = [string]$userAppKey.GetValue(
                    '', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                if (-not [string]::IsNullOrWhiteSpace($userDefaultPath)) {
                    $candidates.Add([Environment]::ExpandEnvironmentVariables($userDefaultPath))
                }
            }
        }
    }

    $resolved = @($candidates | Select-Object -Unique | Where-Object {
            Test-Path -LiteralPath $_ -PathType Leaf -ErrorAction Stop
        })
    if ($resolved.Count -eq 0) {
        return [PSCustomObject]@{
            Installed = $false
            Path      = $null
            Version   = $null
            Major     = $null
            Paths     = @()
            Installations = @()
            UnreadablePaths = @()
        }
    }

    $resolvedVersions = @()
    $unreadablePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($resolvedPath in $resolved) {
        $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
        $versionText = [string]$item.VersionInfo.FileVersion
        [version]$version = $null
        if ([string]::IsNullOrWhiteSpace($versionText) -or
            -not [version]::TryParse(($versionText -replace '[^0-9.].*$', ''), [ref]$version)) {
            $unreadablePaths.Add([string]$resolvedPath)
            continue
        }
        $resolvedVersions += [PSCustomObject]@{ Path = $resolvedPath; Version = $version }
    }
    if ($resolvedVersions.Count -eq 0) {
        throw 'Microsoft Edge executable candidates were found, but none had a parseable file version'
    }
    # Applicability follows the newest installed executable that can consume
    # the machine policy. Older residual copies remain in Paths for diagnosis
    # but must not shrink the policy set of the current installation.
    $selected = @($resolvedVersions | Sort-Object Version, Path -Descending)[0]
    return [PSCustomObject]@{
        Installed = $true
        Path      = [string]$selected.Path
        Version   = ([version]$selected.Version).ToString()
        Major     = [int]([version]$selected.Version).Major
        Paths     = @($resolved | ForEach-Object { [string]$_ })
        Installations = @($resolvedVersions | ForEach-Object {
                [PSCustomObject]@{
                    Path = [string]$_.Path
                    Version = ([version]$_.Version).ToString()
                }
            })
        UnreadablePaths = @($unreadablePaths)
    }
}
