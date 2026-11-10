#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Core/HiddenWorker.ps1')
}

Describe 'Console-free original-user worker launcher' {
    BeforeAll {
        function Read-StagedBytes {
            param([Parameter(Mandatory)][string]$Path)
            # The staging handle holds DELETE access; a reader must share it.
            $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try {
                $bytes = [byte[]]::new($stream.Length)
                $null = $stream.Read($bytes, 0, $bytes.Length)
                $bytes
            } finally { $stream.Dispose() }
        }
        function Invoke-Dispatcher {
            param([Parameter(Mandatory)]$Launch)
            $process = [Diagnostics.Process]::new()
            $process.StartInfo.FileName = $Launch.Action.Execute
            $process.StartInfo.Arguments = $Launch.Action.Arguments
            $process.StartInfo.UseShellExecute = $false
            $process.StartInfo.CreateNoWindow = $true
            $null = $process.Start()
            if (-not $process.WaitForExit(60000)) { $process.Kill(); throw 'Dispatcher did not finish' }
            $process.ExitCode
        }
    }

    BeforeEach {
        Mock New-ScheduledTaskAction { param($Execute,$Argument) [pscustomobject]@{Execute=$Execute;Arguments=$Argument} }
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('exit 17'))
        $sid = 'S-1-5-21-1-2-3-1001'
        $null = $encoded, $sid
    }

    It 'stages a hash-bound request and launches installed PowerShell without creating an executable' {
        $launch = New-NoIDHiddenWorkerTaskAction -EncodedCommand $encoded -UserSid $sid -SessionId 1
        try {
            $launch.Action.Execute | Should -BeExactly (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')
            $launch.Action.Arguments.Length | Should -BeLessThan 30000
            $launch.Principal.LogonType | Should -Be 'ServiceAccount'
            $requestPath = Join-Path $launch.LauncherDirectory 'request.json'
            $requestBytes = Read-StagedBytes -Path $requestPath
            $request = [Text.Encoding]::UTF8.GetString($requestBytes) | ConvertFrom-Json
            $request.EncodedCommand | Should -BeExactly $encoded
            $request.UserSid | Should -BeExactly $sid
            $request.SessionId | Should -Be 1
            @(Get-ChildItem -LiteralPath $launch.LauncherDirectory).Count | Should -Be 2
            @(Get-ChildItem -LiteralPath $launch.LauncherDirectory -Filter '*.exe').Count | Should -Be 0
            # While the staged files are open, Windows refuses to move the folder.
            { [IO.Directory]::Move($launch.LauncherDirectory, $launch.LauncherDirectory + '-moved') } | Should -Throw
            foreach ($file in Get-ChildItem -LiteralPath $launch.LauncherDirectory) {
                $acl = Get-Acl -LiteralPath $file.FullName
                $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
                $rules.Count | Should -Be 2
                @($rules | Where-Object { $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') }).Count | Should -Be 0
                # Nobody else can write a staged file while it is in use.
                { [IO.File]::Open($file.FullName, 'Open', 'ReadWrite', 'ReadWrite, Delete').Dispose() } | Should -Throw
            }
            $scriptText = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($launch.Action.Arguments -split ' ')[-1]))
            $errors = $null; $tokens = $null
            $null = [Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$tokens, [ref]$errors)
            @($errors).Count | Should -Be 0
            # The task definition names exactly the staged bytes.
            $scriptText | Should -Match ([regex]::Escape("'request.json'='$(Get-NoIDHiddenWorkerDigest -Bytes $requestBytes)'"))
            $source = [IO.File]::ReadAllBytes((Join-Path $repo 'Core/HiddenWorker.cs'))
            $scriptText | Should -Match ([regex]::Escape("'worker.cs'='$(Get-NoIDHiddenWorkerDigest -Bytes $source)'"))
        } finally { Remove-NoIDHiddenWorkerLauncher -Launcher $launch -Confirm:$false }
        Test-Path -LiteralPath $launch.LauncherDirectory | Should -BeFalse
    }

    It 'runs only staged bytes: a replaced input ends the dispatcher before any token use' {
        $launch = New-NoIDHiddenWorkerTaskAction -EncodedCommand $encoded -UserSid $sid -SessionId 1
        $planted = @()
        try {
            # Intact input passes the digest check and compiles; only the SYSTEM
            # identity check (code 87) stops it in a test process.
            Invoke-Dispatcher -Launch $launch | Should -Be 87
            $source = [IO.File]::ReadAllBytes((Join-Path $repo 'Core/HiddenWorker.cs'))
            foreach ($stream in $launch.StagedFiles) { $stream.Dispose() }
            $other = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('exit 18'))
            $replacement = @{
                'worker.cs' = $source
                'request.json' = [Text.UTF8Encoding]::new($false).GetBytes(([ordered]@{EncodedCommand=$other;UserSid=$sid;SessionId=1} | ConvertTo-Json -Compress))
            }
            foreach ($name in $replacement.Keys) {
                $path = Join-Path $launch.LauncherDirectory $name
                [IO.File]::WriteAllBytes($path, $replacement[$name])
                $planted += $path
            }
            Invoke-Dispatcher -Launch $launch | Should -Be 13
        } finally {
            foreach ($path in $planted) { [IO.File]::Delete($path) }
            Remove-NoIDHiddenWorkerLauncher -Launcher $launch -Confirm:$false
        }
        Test-Path -LiteralPath $launch.LauncherDirectory | Should -BeFalse
    }

    It 'rejects non-base64 or malformed command arguments before creating a task' -TestCases @(
        @{Value='AA== & calc'}, @{Value='AAA'}, @{Value=('A' * 28004)}
    ) {
        param($Value)
        $null = $Value
        { New-NoIDHiddenWorkerTaskAction -EncodedCommand $Value -UserSid $sid -SessionId 1 } | Should -Throw
        Should -Invoke New-ScheduledTaskAction -Times 0 -Exactly
    }

    It 'rejects session zero before staging a user request' {
        { New-NoIDHiddenWorkerTaskAction -EncodedCommand $encoded -UserSid $sid -SessionId 0 } | Should -Throw
        Should -Invoke New-ScheduledTaskAction -Times 0 -Exactly
    }

    It 'refuses a directory made accessible to an untrusted account' {
        $launch = New-NoIDHiddenWorkerTaskAction -EncodedCommand $encoded -UserSid $sid -SessionId 1
        $original = Get-Acl -LiteralPath $launch.LauncherDirectory
        try {
            $changed = Get-Acl -LiteralPath $launch.LauncherDirectory
            $changed.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
            Set-Acl -LiteralPath $launch.LauncherDirectory -AclObject $changed
            { Assert-NoIDHiddenWorkerDirectory -DirectoryPath $launch.LauncherDirectory } | Should -Throw "*permissions are unsafe: $($launch.LauncherDirectory)"
        } finally {
            Set-Acl -LiteralPath $launch.LauncherDirectory -AclObject $original
            Remove-NoIDHiddenWorkerLauncher -Launcher $launch -Confirm:$false
        }
    }

    It 'refuses cleanup outside the exact generated launcher directory shape' {
        { Remove-NoIDHiddenWorkerLauncher -Launcher ([pscustomobject]@{LauncherDirectory=$TestDrive}) -Confirm:$false } | Should -Throw '*Unexpected*'
        Test-Path -LiteralPath $TestDrive | Should -BeTrue
    }

    It 'preserves unexpected content during nonrecursive cleanup' {
        $launch = New-NoIDHiddenWorkerTaskAction -EncodedCommand $encoded -UserSid $sid -SessionId 1
        $sentinel = Join-Path $launch.LauncherDirectory 'keep.txt'
        try {
            Set-Content -LiteralPath $sentinel -Value 'preserve'
            { Remove-NoIDHiddenWorkerLauncher -Launcher $launch -Confirm:$false } | Should -Throw
            (Get-Content -LiteralPath $sentinel) | Should -BeExactly 'preserve'
            # The staged files themselves were deleted through their handles.
            (@(Get-ChildItem -LiteralPath $launch.LauncherDirectory) | ForEach-Object Name) -join ',' | Should -BeExactly 'keep.txt'
        } finally {
            Remove-Item -LiteralPath $sentinel -ErrorAction SilentlyContinue
            Remove-NoIDHiddenWorkerLauncher -Launcher $launch -Confirm:$false
        }
    }

    It 'compiles the native launcher and rejects malformed requests before acquiring a token' {
        if (-not ('NoIDHiddenWorker' -as [type])) { Add-Type -Path (Join-Path $repo 'Core/HiddenWorker.cs') }
        { [NoIDHiddenWorker]::Run($encoded, $sid, 0) } | Should -Throw
        { [NoIDHiddenWorker]::Run('invalid!', $sid, 1) } | Should -Throw
        { [NoIDHiddenWorker]::Run($encoded, 'S-1-5-18', 1) } | Should -Throw
    }
}

Describe 'Original-user task failure detection' {
    BeforeEach {
        $script:WorkerFixture = [pscustomobject]@{ State=3; LastTaskResult=2147942405; LastRunTime=[DateTime]::Now }
        $folder = [pscustomobject]@{}
        $folder | Add-Member ScriptMethod GetTask { param($TaskName) $null=$TaskName; $script:WorkerFixture }
        $service = [pscustomobject]@{ Folder=$folder }
        $service | Add-Member ScriptMethod Connect {}
        $service | Add-Member ScriptMethod GetFolder { param($Path) $null=$Path; $this.Folder }
        Mock New-Object { $service } -ParameterFilter { $ComObject -eq 'Schedule.Service' }
        $resultPath = Join-Path $TestDrive 'result.json'
        $null = $resultPath
    }

    It 'reports a rejected task immediately instead of waiting for the worker deadline' {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        { Assert-NoIDHiddenWorkerTaskPending -TaskName 'fixture' -ResultPath $resultPath } | Should -Throw '*2147942405*'
        $timer.Elapsed.TotalSeconds | Should -BeLessThan 2
    }

    It 'allows queued and running tasks to finish' -TestCases @(@{State=2},@{State=4}) {
        param($State)
        $script:WorkerFixture.State = $State
        { Assert-NoIDHiddenWorkerTaskPending -TaskName 'fixture' -ResultPath $resultPath } | Should -Not -Throw
    }

    It 'allows a not-yet-started task to start' {
        $script:WorkerFixture.LastTaskResult = 267011
        { Assert-NoIDHiddenWorkerTaskPending -TaskName 'fixture' -ResultPath $resultPath } | Should -Not -Throw
    }

    It 'names a changed staged input' {
        $script:WorkerFixture.LastTaskResult = 13
        { Assert-NoIDHiddenWorkerTaskPending -TaskName 'fixture' -ResultPath $resultPath } | Should -Throw '*task result=13: its staged input changed after staging and was not run'
    }

    It 'rejects successful exit without the required result' {
        $script:WorkerFixture.LastTaskResult = 0
        { Assert-NoIDHiddenWorkerTaskPending -TaskName 'fixture' -ResultPath $resultPath } | Should -Throw '*task result=0*'
    }

    It 'accepts a result published between the caller check and task-state lookup' {
        $script:WorkerFixture.LastTaskResult = 0
        Set-Content -LiteralPath $resultPath -Value '{}'
        { Assert-NoIDHiddenWorkerTaskPending -TaskName 'fixture' -ResultPath $resultPath } | Should -Not -Throw
    }
}
