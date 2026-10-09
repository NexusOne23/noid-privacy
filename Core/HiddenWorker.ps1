#Requires -Version 5.1

$script:NoIDHiddenWorkerSource = Join-Path $PSScriptRoot 'HiddenWorker.cs'
$script:NoIDHiddenWorkerFiles = @('worker.cs', 'request.json')

function Get-NoIDHiddenWorkerDigest {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try { return -join ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
}

function Assert-NoIDHiddenWorkerDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DirectoryPath)

    $parent = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([IO.Path]::GetDirectoryName($DirectoryPath) -cne $parent -or
        [IO.Path]::GetFileName($DirectoryPath) -cnotmatch '^NoID-HiddenWorker-[0-9a-f]{32}$') {
        throw "Unexpected hidden worker directory path: $DirectoryPath"
    }
    # The dispatcher runs only bytes whose SHA-256 its task definition names,
    # so the permissions of ProgramData and its parents are not relied on.
    $directory = [IO.DirectoryInfo]::new($DirectoryPath)
    if (-not $directory.Exists -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Hidden worker directory is missing or redirected: $DirectoryPath"
    }
    $acl = $directory.GetAccessControl()
    if (-not $acl.AreAccessRulesProtected -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
        throw "Hidden worker directory ownership or inheritance is unsafe: $DirectoryPath"
    }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw "Hidden worker directory permissions are unsafe: $DirectoryPath" }
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $grant = @($rules | Where-Object { $_.IdentityReference.Value -ceq $sid })
        if ($grant.Count -ne 1 -or $grant[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $grant[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $grant[0].InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or
            $grant[0].PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "Hidden worker directory permissions are unsafe: $DirectoryPath"
        }
    }
}

function New-NoIDHiddenWorkerTaskAction {
    <#
    .SYNOPSIS
        Creates a console-free launcher for an original-user task.
    .DESCRIPTION
        A transient SYSTEM dispatcher uses the logged-on user's Windows token.
        Split administrator tokens are reduced to their limited half. The
        worker itself runs as that user, never as SYSTEM. Only the installed
        Windows PowerShell is launched, so no new executable needs ASR reputation.
        The task definition names the SHA-256 of the request and interop
        source; the dispatcher runs only the bytes it read and verified, so a
        replaced file or folder cannot change what SYSTEM executes. The staged
        files stay open until Remove-NoIDHiddenWorkerLauncher deletes them
        through these handles. A kernel job ends descendants when the task is
        stopped. Remove the launcher after stopping/removing the task.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9+/]+={0,2}$')][string]$EncodedCommand,
        [Parameter(Mandatory)][ValidatePattern('^S-1-(?:5-21|12-1)-[0-9-]+$')][string]$UserSid,
        [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$SessionId
    )
    if ($EncodedCommand.Length -gt 28000 -or $EncodedCommand.Length % 4 -ne 0) {
        throw 'Hidden worker command length is invalid'
    }
    $null = [Convert]::FromBase64String($EncodedCommand)
    $caller = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $caller.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Hidden worker creation requires an elevated administrator token'
    }
    $source = [IO.File]::ReadAllBytes($script:NoIDHiddenWorkerSource)
    if ($source.Length -lt 1 -or $source.Length -gt 131072) { throw 'Hidden worker source length is invalid' }
    $parent = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $directoryPath = Join-Path $parent ('NoID-HiddenWorker-' + [Guid]::NewGuid().ToString('N'))
    if (-not $PSCmdlet.ShouldProcess($directoryPath, 'Stage original-user worker dispatcher')) { return }
    $directory = [IO.DirectoryInfo]::new($directoryPath)
    $created = $false
    $staged = [Collections.Generic.List[IO.FileStream]]::new()
    try {
        if ($directory.Exists -or [IO.File]::Exists($directoryPath)) { throw "Hidden worker path already exists: $directoryPath" }
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
        }
        $directory.Create($security)
        # Validate before trusting or cleaning up a path that may have existed
        # at the instant of creation. CreateNew never overwrites planted files.
        Assert-NoIDHiddenWorkerDirectory -DirectoryPath $directoryPath
        $created = $true
        $request = [ordered]@{ EncodedCommand=$EncodedCommand; UserSid=$UserSid; SessionId=$SessionId }
        $files = @{
            'worker.cs' = $source
            'request.json' = [Text.UTF8Encoding]::new($false).GetBytes(($request | ConvertTo-Json -Compress))
        }
        $digests = @{}
        foreach ($name in $script:NoIDHiddenWorkerFiles) {
            # Readers may share this handle, writers may not. Closing it deletes
            # exactly this file, never whatever a path resolves to later.
            $stream = [IO.FileStream]::new((Join-Path $directoryPath $name), [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, [IO.FileOptions]::DeleteOnClose)
            $staged.Add($stream)
            $stream.Write($files[$name], 0, $files[$name].Length)
            $stream.Flush()
            $digests[$name] = Get-NoIDHiddenWorkerDigest -Bytes $files[$name]
        }
        $escapedPath = $directoryPath.Replace("'", "''")
        $dispatcher = "`$ErrorActionPreference='Stop'; `$directoryPath='$escapedPath'; " +
            "`$expected=@{'worker.cs'='$($digests['worker.cs'])'; 'request.json'='$($digests['request.json'])'}; " + @'
try {
    $inputs = @{}
    foreach ($name in @('worker.cs', 'request.json')) {
        # The staging handle holds DELETE access, so a reader must share it.
        $stream = [IO.FileStream]::new((Join-Path $directoryPath $name), [IO.FileMode]::Open, [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            if ($stream.Length -lt 1 -or $stream.Length -gt 131072) { exit 13 }
            $bytes = [byte[]]::new($stream.Length)
            $read = 0
            while ($read -lt $bytes.Length) {
                $count = $stream.Read($bytes, $read, $bytes.Length - $read)
                if ($count -le 0) { exit 13 }
                $read += $count
            }
        } finally { $stream.Dispose() }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
        # Only bytes named by this task definition run. Code 13 (invalid data)
        # reports a changed or replaced input before any user token is used.
        if ($digest -cne $expected[$name]) { exit 13 }
        $inputs[$name] = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    $request = $inputs['request.json'] | ConvertFrom-Json
    Add-Type -TypeDefinition $inputs['worker.cs'] -ErrorAction Stop
    exit ([NoIDHiddenWorker]::Run([string]$request.EncodedCommand, [string]$request.UserSid, [int]$request.SessionId))
} catch { exit 87 }
'@
        $dispatcherEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($dispatcher))
        if ($dispatcherEncoded.Length -gt 28000) { throw 'Hidden worker dispatcher command is too long' }
        $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        return [pscustomobject]@{
            Action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $dispatcherEncoded"
            Principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
            LauncherDirectory = $directoryPath
            StagedFiles = $staged.ToArray()
        }
    }
    catch {
        if ($created) {
            $launcher = [pscustomobject]@{ LauncherDirectory=$directoryPath; StagedFiles=$staged.ToArray() }
            Remove-NoIDHiddenWorkerLauncher -Launcher $launcher -Confirm:$false
        }
        throw
    }
}

function Assert-NoIDHiddenWorkerTaskPending {
    <# A task that has already failed cannot produce a result by waiting longer. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$ResultPath
    )

    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $task = $service.GetFolder('\').GetTask($TaskName)
    if ([int]$task.State -in @(2, 4)) { return } # Queued / Running
    $result = [int64]$task.LastTaskResult
    if ($result -eq 267011 -or ($result -eq 0 -and $task.LastRunTime.Year -lt 2000)) { return } # Not started yet
    # The worker may have finished between the caller's check and this read.
    if (Test-Path -LiteralPath $ResultPath -PathType Leaf) { return }
    if ($result -eq 13) {
        throw "Original-user worker ended without a result; task result=13: its staged input changed after staging and was not run"
    }
    throw "Original-user worker ended without a result; task result=$result"
}

function Remove-NoIDHiddenWorkerLauncher {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param([Parameter(Mandatory)][object]$Launcher)

    $directoryPath = [string]$Launcher.LauncherDirectory
    $parent = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([IO.Path]::GetDirectoryName($directoryPath) -cne $parent -or
        [IO.Path]::GetFileName($directoryPath) -cnotmatch '^NoID-HiddenWorker-[0-9a-f]{32}$') {
        throw "Unexpected hidden worker cleanup path: $directoryPath"
    }
    if (-not $PSCmdlet.ShouldProcess($directoryPath, 'Remove temporary hidden worker launcher')) { return }
    # Closing a staging handle deletes the file it created. No path is resolved
    # again, so a redirected folder cannot redirect the deletion.
    foreach ($stream in @($Launcher.StagedFiles)) {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    $directory = [IO.DirectoryInfo]::new($directoryPath)
    if (-not $directory.Exists) { return }
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        # Deleting a directory reparse point removes only the link.
        [IO.Directory]::Delete($directoryPath, $false)
        throw "Hidden worker directory was replaced by a reparse point: $directoryPath"
    }
    # A scanner that still has a deleted file open keeps its name briefly.
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt 5 -and
        @($directory.GetFileSystemInfos() | Where-Object { $_.Name -cin $script:NoIDHiddenWorkerFiles }).Count -gt 0) {
        Start-Sleep -Milliseconds 100
    }
    # Nonrecursive: unknown content is preserved and reported, never traversed.
    [IO.Directory]::Delete($directoryPath, $false)
}
