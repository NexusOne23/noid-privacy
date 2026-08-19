#Requires -Version 5.1

$script:AdvancedSecurityWinInetHelperPath = $PSCommandPath

function Initialize-AdvancedSecurityWinInetApi {
    [CmdletBinding()]
    param()

    if ('NoID.AdvancedSecurityWinInet' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace NoID
{
    public static class AdvancedSecurityWinInet
    {
        private const int InternetOptionRefresh = 37;
        private const int InternetOptionSettingsChanged = 39;
        private const int InternetOptionPerConnectionOption = 75;
        private const int InternetOptionProxySettingsChanged = 95;
        private const int InternetPerConnFlags = 1;
        private const int InternetPerConnFlagsUi = 10;

        [StructLayout(LayoutKind.Explicit)]
        private struct OptionValue
        {
            [FieldOffset(0)] public UInt32 Integer;
            [FieldOffset(0)] public IntPtr Pointer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PerConnectionOption
        {
            public int Option;
            public OptionValue Value;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct PerConnectionOptionList
        {
            public int Size;
            public IntPtr Connection;
            public int OptionCount;
            public int OptionError;
            public IntPtr Options;
        }

        [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern bool InternetQueryOption(
            IntPtr internet,
            int option,
            ref PerConnectionOptionList buffer,
            ref int bufferLength);

        [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern bool InternetSetOption(
            IntPtr internet,
            int option,
            ref PerConnectionOptionList buffer,
            int bufferLength);

        [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern bool InternetSetOption(
            IntPtr internet,
            int option,
            IntPtr buffer,
            int bufferLength);

        private static Win32Exception Failure(string operation)
        {
            return new Win32Exception(Marshal.GetLastWin32Error(), operation + " failed");
        }

        public static UInt32 QueryFlags()
        {
            int optionSize = Marshal.SizeOf(typeof(PerConnectionOption));
            IntPtr options = Marshal.AllocCoTaskMem(optionSize);
            try
            {
                PerConnectionOption item = new PerConnectionOption();
                item.Option = InternetPerConnFlagsUi;
                Marshal.StructureToPtr(item, options, false);

                PerConnectionOptionList list = new PerConnectionOptionList();
                list.Size = Marshal.SizeOf(typeof(PerConnectionOptionList));
                list.Connection = IntPtr.Zero;
                list.OptionCount = 1;
                list.Options = options;
                int listSize = list.Size;
                if (!InternetQueryOption(IntPtr.Zero, InternetOptionPerConnectionOption, ref list, ref listSize))
                {
                    item.Option = InternetPerConnFlags;
                    Marshal.StructureToPtr(item, options, false);
                    listSize = list.Size;
                    if (!InternetQueryOption(IntPtr.Zero, InternetOptionPerConnectionOption, ref list, ref listSize))
                        throw Failure("InternetQueryOption(PER_CONNECTION_OPTION)");
                }

                item = (PerConnectionOption)Marshal.PtrToStructure(options, typeof(PerConnectionOption));
                return item.Value.Integer;
            }
            finally
            {
                Marshal.FreeCoTaskMem(options);
            }
        }

        public static void SetFlags(UInt32 flags)
        {
            int optionSize = Marshal.SizeOf(typeof(PerConnectionOption));
            IntPtr options = Marshal.AllocCoTaskMem(optionSize);
            try
            {
                PerConnectionOption item = new PerConnectionOption();
                item.Option = InternetPerConnFlags;
                item.Value.Integer = flags;
                Marshal.StructureToPtr(item, options, false);

                PerConnectionOptionList list = new PerConnectionOptionList();
                list.Size = Marshal.SizeOf(typeof(PerConnectionOptionList));
                list.Connection = IntPtr.Zero;
                list.OptionCount = 1;
                list.Options = options;
                if (!InternetSetOption(IntPtr.Zero, InternetOptionPerConnectionOption, ref list, list.Size))
                    throw Failure("InternetSetOption(PER_CONNECTION_OPTION)");
            }
            finally
            {
                Marshal.FreeCoTaskMem(options);
            }

            if (!InternetSetOption(IntPtr.Zero, InternetOptionProxySettingsChanged, IntPtr.Zero, 0))
                throw Failure("InternetSetOption(PROXY_SETTINGS_CHANGED)");
            if (!InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0))
                throw Failure("InternetSetOption(SETTINGS_CHANGED)");
            if (!InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0))
                throw Failure("InternetSetOption(REFRESH)");
        }
    }
}
'@ -ErrorAction Stop
}

function Get-AdvancedSecurityInteractiveUser {
    <#
    .SYNOPSIS
        Resolve the Explorer owner in the caller's Windows session.

    .DESCRIPTION
        The elevated process identity may be a separate administrator account.
        WinINet user settings belong to the account owning Explorer in the
        current session, so HKCU of the elevated process is not authoritative.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [switch]$AllowNone
    )

    $sessionId = [int][System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $lastResolutionError = $null
    $lastAttemptHadNoExplorer = $false
    $resolvedIdentity = $null

    # Get-Process -IncludeUserName can omit a process when owner lookup fails.
    # That makes an API failure indistinguishable from a logged-off user. Use
    # the documented Win32_Process owner methods, validate their return codes,
    # and retry a bounded number of times if Explorer restarts mid-snapshot.
    foreach ($attempt in 1..3) {
        $lastAttemptHadNoExplorer = $false
        try {
            $explorerProcesses = @(Get-CimInstance -ClassName Win32_Process `
                -Filter "Name = 'explorer.exe'" -ErrorAction Stop |
                Where-Object { [int]$_.SessionId -eq $sessionId })
            if ($explorerProcesses.Count -eq 0) {
                $lastAttemptHadNoExplorer = $true
                throw "No interactive Explorer process is available in Windows session $sessionId"
            }

            $identities = [System.Collections.Generic.List[object]]::new()
            foreach ($process in $explorerProcesses) {
                $ownerSid = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
                if ([uint32]$ownerSid.ReturnValue -ne 0 -or
                    [string]::IsNullOrWhiteSpace([string]$ownerSid.Sid)) {
                    throw "Explorer owner SID query failed with result $($ownerSid.ReturnValue)"
                }
                $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
                if ([uint32]$owner.ReturnValue -ne 0 -or
                    [string]::IsNullOrWhiteSpace([string]$owner.User)) {
                    throw "Explorer owner account query failed with result $($owner.ReturnValue)"
                }
                $account = if ([string]::IsNullOrWhiteSpace([string]$owner.Domain)) {
                    [string]$owner.User
                }
                else {
                    "$($owner.Domain)\$($owner.User)"
                }
                $identities.Add([PSCustomObject]@{
                        Account = $account
                        Sid     = [string]$ownerSid.Sid
                    })
            }

            $sids = @($identities | ForEach-Object { [string]$_.Sid } | Sort-Object -Unique)
            $accounts = @($identities | ForEach-Object { [string]$_.Account } | Sort-Object -Unique)
            if ($sids.Count -ne 1 -or $accounts.Count -ne 1) {
                throw "Interactive Explorer user identity is ambiguous in Windows session $sessionId"
            }
            $resolvedIdentity = [PSCustomObject]@{
                Account = $accounts[0]
                Sid     = $sids[0]
            }
            break
        }
        catch {
            $lastResolutionError = $_.Exception.Message
            if ($attempt -lt 3) {
                Start-Sleep -Milliseconds (200 * $attempt)
            }
        }
    }

    if ($null -eq $resolvedIdentity) {
        if ($AllowNone -and $lastAttemptHadNoExplorer) {
            return $null
        }
        throw "Unable to resolve the interactive Explorer user after 3 attempts: $lastResolutionError"
    }

    $sid = [string]$resolvedIdentity.Sid
    if ($sid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$') {
        throw "Unsupported interactive user SID: $sid"
    }
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Global -ErrorAction Stop
    }
    $hiveRoot = "HKU:\$sid"
    if (-not (Test-Path -LiteralPath $hiveRoot -PathType Container)) {
        throw "Interactive user registry hive is not loaded: $hiveRoot"
    }

    return [PSCustomObject]@{
        Account   = [string]$resolvedIdentity.Account
        Sid       = $sid
        SessionId = $sessionId
        HiveRoot  = $hiveRoot
    }
}

function Invoke-AdvancedSecurityWinInetWorker {
    <#
    .SYNOPSIS
        Query or set WinINet flags inside the actual interactive user's token.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Query', 'SetAutoDetect')]
        [string]$Operation,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^S-1-(?:5-21|12-1)-[0-9-]+$')]
        [string]$ExpectedSid,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ExpectedSessionId,

        [bool]$AutoDetectEnabled = $false,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $record = [ordered]@{
        SchemaVersion = 1
        CapturedUtc   = [DateTime]::UtcNow.ToString('o')
        Operation     = $Operation
        User          = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Sid           = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        SessionId     = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        BeforeFlags   = $null
        RequestedAutoDetect = $(if ($Operation -eq 'SetAutoDetect') { [bool]$AutoDetectEnabled } else { $null })
        Flags         = $null
        AutoDetectEnabled = $null
        Changed       = $false
        Success       = $false
        Error         = $null
    }

    try {
        if ([string]$record.Sid -cne $ExpectedSid -or [int]$record.SessionId -ne $ExpectedSessionId) {
            throw "WinINet worker identity mismatch: $($record.Sid)/$($record.SessionId)"
        }
        Initialize-AdvancedSecurityWinInetApi
        $record.BeforeFlags = [uint32][NoID.AdvancedSecurityWinInet]::QueryFlags()
        if ($Operation -eq 'SetAutoDetect') {
            # This module owns only PROXY_TYPE_AUTO_DETECT (0x8). Preserve every
            # other current flag, including flags introduced by future Windows
            # versions or changed by the user after Apply.
            $requestedFlags = if ($AutoDetectEnabled) {
                [uint32]$record.BeforeFlags -bor [uint32]8
            }
            else {
                [uint32]$record.BeforeFlags -band [uint32]4294967287
            }
            if ([uint32]$record.BeforeFlags -ne [uint32]$requestedFlags) {
                [NoID.AdvancedSecurityWinInet]::SetFlags([uint32]$requestedFlags)
                $record.Changed = $true
            }
        }
        $record.Flags = [uint32][NoID.AdvancedSecurityWinInet]::QueryFlags()
        $record.AutoDetectEnabled = (([uint32]$record.Flags -band [uint32]8) -ne 0)
        if ($Operation -eq 'SetAutoDetect' -and
            [bool]$record.AutoDetectEnabled -ne [bool]$AutoDetectEnabled) {
            throw "WinINet AutoDetect verification failed: expected $AutoDetectEnabled, got $($record.AutoDetectEnabled)"
        }
        $record.Success = $true
    }
    catch {
        $record.Error = $_.Exception.ToString()
    }

    $parent = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "WinINet worker output directory is unavailable: $parent"
    }
    # Publish through a same-directory rename so the privileged reader can
    # never observe a partially written JSON document.
    $temporaryOutputPath = $OutputPath + '.tmp'
    [System.IO.File]::WriteAllText(
        $temporaryOutputPath,
        ($record | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporaryOutputPath -Destination $OutputPath -Force -ErrorAction Stop
    return [PSCustomObject]$record
}

function Invoke-AdvancedSecurityWinInetUserState {
    <#
    .SYNOPSIS
        Execute the documented WinINet API in the interactive user's token.

    .DESCRIPTION
        A transient limited-privilege scheduled task supplies the already
        logged-on Explorer token without requesting or persisting credentials.
        The task and its ACL-scoped ProgramData exchange directory are removed
        in a finally block.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        $User,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Query', 'SetAutoDetect')]
        [string]$Operation,

        [bool]$AutoDetectEnabled = $false,

        [ValidateRange(5, 120)]
        [int]$TimeoutSeconds = 120
    )

    foreach ($property in @('Account', 'Sid', 'SessionId')) {
        if (-not $User.PSObject.Properties[$property]) {
            throw "WinINet user context is missing '$property'"
        }
    }
    $sid = [string]$User.Sid
    $sessionId = [int]$User.SessionId
    if ($sid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$' -or $sessionId -lt 1) {
        throw 'WinINet user context is invalid'
    }

    $currentUser = Get-AdvancedSecurityInteractiveUser
    if ([string]$currentUser.Sid -cne $sid -or [int]$currentUser.SessionId -ne $sessionId) {
        throw 'Interactive user identity changed before the WinINet operation'
    }
    if (-not (Test-Path -LiteralPath $script:AdvancedSecurityWinInetHelperPath -PathType Leaf)) {
        throw "WinINet helper source is unavailable: $script:AdvancedSecurityWinInetHelperPath"
    }

    $identifier = [Guid]::NewGuid().ToString('N')
    $taskName = "NoID-WinInet-$identifier"
    $exchangeDirectory = Join-Path $env:ProgramData $taskName
    $resultPath = Join-Path $exchangeDirectory 'result.json'
    $taskRegistered = $false
    try {
        $directory = New-Item -ItemType Directory -Path $exchangeDirectory -ErrorAction Stop
        $security = [System.Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        foreach ($access in @(
                @{ Sid='S-1-5-18'; Rights=[System.Security.AccessControl.FileSystemRights]::FullControl }
                @{ Sid='S-1-5-32-544'; Rights=[System.Security.AccessControl.FileSystemRights]::FullControl }
                @{ Sid=$sid; Rights=[System.Security.AccessControl.FileSystemRights]::Modify }
            )) {
            $identity = [System.Security.Principal.SecurityIdentifier]::new([string]$access.Sid)
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $identity,
                [System.Security.AccessControl.FileSystemRights]$access.Rights,
                $inheritance,
                $propagation,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $null = $security.AddAccessRule($rule)
        }
        $directory.SetAccessControl($security)

        $escapedHelper = $script:AdvancedSecurityWinInetHelperPath.Replace("'", "''")
        $escapedOutput = $resultPath.Replace("'", "''")
        $autoDetectLiteral = if ($AutoDetectEnabled) { '$true' } else { '$false' }
        $workerCommand = "& { . '$escapedHelper'; " +
            "`$result = Invoke-AdvancedSecurityWinInetWorker -Operation '$Operation' " +
            "-ExpectedSid '$sid' -ExpectedSessionId $sessionId -AutoDetectEnabled:$autoDetectLiteral -OutputPath '$escapedOutput'; " +
            "if (-not `$result.Success) { exit 1 } }"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($workerCommand))
        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $action = New-ScheduledTaskAction -Execute $powershell `
            -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
        $principal = New-ScheduledTaskPrincipal -UserId ([string]$User.Account) -LogonType Interactive -RunLevel Limited
        # The caller owns the fail-closed deadline. Keep the independent task
        # limit just beyond it so both clocks cannot race while a fresh Windows
        # PowerShell worker is publishing the atomic result document.
        $schedulerExecutionLimitSeconds = [int]$TimeoutSeconds + 5
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Seconds $schedulerExecutionLimitSeconds)
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        $taskRegistered = $true
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            $taskState = (Get-ScheduledTask -TaskName $taskName -ErrorAction Stop).State
            if ($taskState -ne 'Running' -and
                (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
                break
            }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $deadline)

        if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
            throw "WinINet user operation timed out; task result=$($taskInfo.LastTaskResult)"
        }
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        if ([int64]$taskInfo.LastTaskResult -ne 0) {
            throw "WinINet user operation task failed with result $($taskInfo.LastTaskResult)"
        }
        $record = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ([int]$record.SchemaVersion -ne 1 -or
            [string]$record.Sid -cne $sid -or
            [int]$record.SessionId -ne $sessionId -or
            [string]$record.Operation -cne $Operation -or
            [string]::IsNullOrWhiteSpace([string]$record.User) -or
            $null -eq $record.BeforeFlags -or
            $null -eq $record.Flags -or
            [uint64]$record.BeforeFlags -gt [uint64][uint32]::MaxValue -or
            [uint64]$record.Flags -gt [uint64][uint32]::MaxValue -or
            $record.AutoDetectEnabled -isnot [bool] -or
            [bool]$record.AutoDetectEnabled -ne (([uint32]$record.Flags -band [uint32]8) -ne 0) -or
            $record.Changed -isnot [bool] -or
            $record.Success -isnot [bool] -or
            -not [bool]$record.Success) {
            throw "WinINet user operation failed validation: $($record.Error)"
        }
        return $record
    }
    finally {
        if ($taskRegistered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $exchangeDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}
